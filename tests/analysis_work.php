<?php
/** Standalone in-memory tests: no WHMCS bootstrap, SQL, DDL, native or API calls. */
namespace WHMCS\Database {
    final class Capsule {
        public static array $tables=[];
        public static function table($name) { return new Query($name); }
        public static function connection() { return new self(); }
        public function transaction($fn) {
            $before=self::$tables;
            try { return $fn(); } catch (\Throwable $e) { self::$tables=$before; throw $e; }
        }
        public function query() { return new Query(''); }
    }
    final class Query {
        private array $filters=[],$orders=[],$columns=[];
        private int $maximum=PHP_INT_MAX;
        private bool $unique=false;
        private ?self $sub=null;
        public function __construct(private string $table) {}
        private static function compare($a,$op,$b): bool {
            return match($op) {'='=>$a==$b,'!='=>$a!=$b,'>'=>$a>$b,'>='=>$a>=$b,'<'=>$a<$b,'<='=>$a<=$b,default=>throw new \LogicException($op)};
        }
        public function where($field,$op=null,$value=null) {
            if (is_callable($field)) { $q=new self($this->table); $field($q); $this->filters[]=fn($r)=>$q->matches($r); }
            else { if (func_num_args()===2) { $value=$op; $op='='; } $this->filters[]=fn($r)=>self::compare($r[$field]??null,$op,$value); }
            return $this;
        }
        public function orWhere($field,$op,$value) {
            $previous=$this->filters; $this->filters=[function($r)use($previous,$field,$op,$value) {
                $ok=true; foreach($previous as $fn) $ok=$ok&&$fn($r);
                return $ok||self::compare($r[$field]??null,$op,$value);
            }]; return $this;
        }
        public function whereNull($field) { $this->filters[]=fn($r)=>($r[$field]??null)===null; return $this; }
        public function whereIn($field,$values) { $this->filters[]=fn($r)=>in_array($r[$field]??null,$values,true); return $this; }
        public function whereColumn($a,$op,$b) { $this->filters[]=fn($r)=>self::compare($r[$a],$op,$r[$b]); return $this; }
        public function orderBy($field) { $this->orders[]=$field; return $this; }
        public function limit($n) { $this->maximum=$n; return $this; }
        public function lockForUpdate() { return $this; }
        public function select($columns) { $this->columns=$columns; return $this; }
        public function distinct() { $this->unique=true; return $this; }
        public function fromSub($query,$alias) { $this->sub=$query; return $this; }
        private function matches($row): bool { foreach($this->filters as $fn) if(!$fn($row))return false; return true; }
        private function rows(): array {
            if($this->sub)return $this->sub->rows();
            $rows=array_values(array_filter(Capsule::$tables[$this->table]??[],fn($r)=>$this->matches($r)));
            if($this->orders)usort($rows,function($a,$b){foreach($this->orders as $field){$cmp=$a[$field]<=>$b[$field];if($cmp)return $cmp;}return 0;});
            if($this->columns)$rows=array_map(fn($r)=>array_intersect_key($r,array_flip($this->columns)),$rows);
            if($this->unique)$rows=array_values(array_unique($rows,SORT_REGULAR));
            return array_slice($rows,0,$this->maximum);
        }
        public function get() { return array_map(fn($r)=>(object)$r,$this->rows()); }
        public function first() { $rows=$this->rows(); return $rows?(object)$rows[0]:null; }
        public function count() { return count($this->rows()); }
        public function exists() { return (bool)$this->rows(); }
        public function insert($row) { Capsule::$tables[$this->table][]=$row; return true; }
        public function insertOrIgnore($row) {
            foreach(Capsule::$tables[$this->table]??[] as $old)
                if($old['key']===$row['key']&&$old['rollup_id']===$row['rollup_id']&&$old['revision']===$row['revision'])return 0;
            $this->insert($row);return 1;
        }
        public function update($values) {
            $count=0;
            foreach(Capsule::$tables[$this->table] as &$row)if($this->matches($row)){$row=array_replace($row,$values);$count++;}
            return $count;
        }
        public function delete() {
            $count=0;$kept=[];
            foreach(Capsule::$tables[$this->table]??[] as $row) {
                if($count<$this->maximum&&$this->matches($row))$count++;else $kept[]=$row;
            }
            Capsule::$tables[$this->table]=$kept;return $count;
        }
    }
}
namespace AMS\Fail2Ban {
    final class Database {
        public static array $config=['schema_version'=>'23','ai_queue_consolidation'=>'1'];
        public static function getConfig($key,$default='') { return self::$config[$key]??$default; }
    }
    final class Policy {
        public static function number($key) { return ['ai_behavior_hours'=>24,'ai_evidence_retention_days'=>30][$key]; }
    }
    final class DecisionMemory {
        public static string $policy='policy-v1';
        public static function policyFingerprint(): string { return self::$policy; }
        public static function lineSignature(string $line,string $ip): ?string { return $line==='unsupported'?null:hash('sha256',$ip.$line); }
        public static function signature(array $row): ?string {
            $samples=is_string($row['samples'])?json_decode($row['samples'],true):$row['samples'];
            if(!is_array($samples)||!empty($row['signature_null']))return null;
            $variants=[];
            foreach($samples as $event){$v=self::lineSignature($event['line'],$row['ip']);if(!$v)return null;$variants[$v]=true;}
            $set=array_keys($variants);sort($set);return hash('sha256',json_encode($set));
        }
    }
    final class BehaviorStore {
        public static array $acks=[];
        public static function acknowledge(array $row): void {
            self::$acks[]=$row;
            \WHMCS\Database\Capsule::table('mod_amssoft_fail2ban_rollups')->where('id',$row['id'])->where('revision',$row['revision'])
                ->update(['analyzed_revision'=>$row['revision']]);
        }
    }
}
namespace {
    if(PHP_SAPI!=='cli')exit(1);
    require dirname(__DIR__).'/lib/AnalysisWork.php';
    use AMS\Fail2Ban\{AnalysisWork as W,Database,DecisionMemory,BehaviorStore};
    use WHMCS\Database\Capsule as C;
    $checks=0;$now=time();$rollups='mod_amssoft_fail2ban_rollups';$suggestions='mod_amssoft_fail2ban_ai_suggestions';
    function check($condition,$message) { global $checks;if(!$condition)throw new RuntimeException($message);$checks++; }
    function row($n,$count=1,$line='same'): array {
        global $now;
        $r=['id'=>hash('sha256','row'.$n),'ip'=>'198.51.100.10','source_log'=>'/var/log/apache2/access.log',
            'pattern'=>hash('sha256','pattern'),'revision'=>1,'analyzed_revision'=>0,'events'=>$count,
            'bucket'=>date('Y-m-d H:i:s',$now-60),'processing_state'=>'pending','retry_at'=>null,
            'blocked_confirmed_at'=>null,'attempts'=>0,'validation_attempts'=>0,'failure_code'=>null];
        $events=[];
        for($i=0;$i<$count;$i++)$events[]=['id'=>hash('sha256',"$n:$i"),'ip'=>$r['ip'],'pattern'=>$r['pattern'],'line'=>$line,'time'=>$now-60];
        $r['samples']=json_encode($events);return $r;
    }
    function resetTables() { global $rollups,$suggestions; C::$tables=[$rollups=>[],$suggestions=>[],W::TABLE=>[],W::BATCH_TABLE=>[]];BehaviorStore::$acks=[]; }
    resetTables();$a=row(1,3);$b=row(2,3);$c=row(3,3);
    $group=W::consolidateRows([$a],[$b,$c],$now)[0];
    check(count($group['_work_refs'])===2&&count($group['_work_events'])===6,'Whole rows fit, overflow remains pending');
    check($group['events']===6&&$group['id']===$a['id'],'Sum context counts without rewriting identity');
    check($group['_work_snapshots']===[$a,$b],'Original snapshots preserved');
    check($group['_work_events']===array_merge(json_decode($a['samples'],true),json_decode($b['samples'],true)),'Every full event preserved');
    check(count(W::consolidateRows([$a,$b],[],$now))===1,'Batch representatives partition once');
    foreach(['ip'=>'198.51.100.11','source_log'=>'/var/log/other','pattern'=>hash('sha256','other'),
        'processing_state'=>'review','retry_at'=>date('Y-m-d H:i:s',$now+60),'blocked_confirmed_at'=>date('Y-m-d H:i:s',$now),
        'bucket'=>date('Y-m-d H:i:s',$now-90000),'analyzed_revision'=>1,'signature_null'=>true] as $field=>$value) {
        $other=array_replace($b,[$field=>$value]);
        check(count(W::consolidateRows([$a],[$other],$now)[0]['_work_refs'])===1,'Do not merge '.$field);
    }
    check(count(W::consolidateRows([$a],[row(4,1,'different raw query or UA')],$now)[0]['_work_refs'])===1,'Raw behavior differs');
    $large=row(5,1,str_repeat('x',32769));$large2=row(6,1,str_repeat('x',32769));
    check(count(W::consolidateRows([$large],[$large2],$now)[0]['_work_refs'])===1,'64 KiB proof bound');
    $pool=[];for($n=100;$n<201;$n++)$pool[]=row($n,1,'different');$pool[]=row(202);
    check(count(W::consolidateRows([row(7)],$pool,$now)[0]['_work_refs'])===1,'Bound scan to 100 rows');
    $legacy=row(8);$legacy['behavior_variants']=null;$legacy['behavior_complete']=0;
    check(count(W::consolidateRows([$legacy],[row(9)],$now)[0]['_work_refs'])===2,'Complete legacy samples with null metadata');
    $hidden=$legacy;$hidden['events']=2;
    check(count(W::consolidateRows([$hidden],[row(9)],$now)[0]['_work_refs'])===1,'Incomplete legacy proof fails closed');
    $tracked=row(10);$tracked['events']=100;$tracked['behavior_complete']=1;
    $tracked['behavior_variants']=json_encode([DecisionMemory::lineSignature('same',$tracked['ip'])]);
    check(count(W::consolidateRows([$tracked],[row(11)],$now)[0]['_work_refs'])===2,'All collector variants represented even with larger context count');
    $tracked['behavior_variants']=json_encode([DecisionMemory::lineSignature('same',$tracked['ip']),DecisionMemory::lineSignature('hidden',$tracked['ip'])]);
    check(count(W::consolidateRows([$tracked],[row(11)],$now)[0]['_work_refs'])===1,'Hidden stored variant cannot be acknowledged through merge');
    resetTables();C::$tables[$rollups]=[$a,$b];$groups=W::consolidate([$a]);
    check(count(C::$tables[W::TABLE])===2,'Pending links recorded for originals');
    check(W::health()['unique_subjects_ready']===1&&W::health()['unique_ready']===1,'Health counts subjects, not raw rows');
    W::finalize($groups[0]);check(count(BehaviorStore::$acks)===2,'Acknowledge every original snapshot');
    W::finalize($groups[0]);check(count(BehaviorStore::$acks)===2,'Terminal links prevent duplicate acknowledgement');
    check(W::consolidate([$a])===[],'Terminal revision not rescheduled');
    $reopened=array_replace($a,['analyzed_revision'=>0,'campaign_signature'=>'new-campaign']);
    C::table($rollups)->where('id',$a['id'])->update(['analyzed_revision'=>0,'campaign_signature'=>'new-campaign']);
    $reopenedWork=W::consolidate([$reopened]);
    check(count($reopenedWork)===1,'New campaign may reopen same revision despite old terminal links');
    W::finalize($reopenedWork[0]);
    check(count(BehaviorStore::$acks)===3,'Reopened campaign revision finalized independently');
    foreach(['revision'=>2,'processing_state'=>'review','retry_at'=>date('Y-m-d H:i:s',$now+600),'attempts'=>1] as $field=>$value) {
        resetTables();C::$tables[$rollups]=[$a,array_replace($b,[$field=>$value])];W::finalize($group);
        check(count(BehaviorStore::$acks)===1&&BehaviorStore::$acks[0]===$a,'CAS preserves current '.$field);
    }
    resetTables();C::$tables[$rollups]=[$a,$b];
    C::$tables[$suggestions]=[['task_id'=>$a['id'],'analysis_key'=>'old revision','status'=>'rejected']];
    W::finalize($group);check(count(BehaviorStore::$acks)===2,'Historic rejection does not block new decision');
    resetTables();C::$tables[$rollups]=[$a,$b];
    C::$tables[$suggestions]=[['task_id'=>$a['id'],'analysis_key'=>hash('sha256',$a['id']."\0".$a['revision']."\0"),'status'=>'rejected']];
    W::finalize($group);check(count(BehaviorStore::$acks)===1,'Exact rejected decision is preserved');
    resetTables();$proofs=[$a['ip']=>$group['_work_events']];$contexts=[$a['ip']=>['task_id'=>$a['id']]];$raw=[['ip'=>$a['ip'],'action'=>'monitor']];
    Database::$config['ai_queue_consolidation']='0';
    check(!W::enabled(),'Toggle disables only consolidation');
    $id=W::saveBatch([$a,$b],$proofs,$contexts,$raw);$next=W::nextBatch();
    check($next===['id'=>$id,'batch'=>[$a,$b],'proofs'=>$proofs,'contexts'=>$contexts,'raw'=>$raw,'done'=>[]],'Checkpoint freezes full arrays independently of toggle');
    W::markItem($id,$a['id']);$next=W::nextBatch();
    check($next['batch']===[$b]&&$next['done']===[$a['id']=>true],'Resume only unresolved with durable done map');
    W::completeBatch($id);check(W::nextBatch()!==null,'Cannot complete unfinished checkpoint');
    W::markItem($id,$b['id']);check(W::nextBatch()===null&&C::$tables[W::BATCH_TABLE][0]['status']==='complete','Last mark completes batch');
    $id=W::saveBatch([$a],$proofs,$contexts,$raw);DecisionMemory::$policy='changed';
    check(W::nextBatch()===null&&C::$tables[W::BATCH_TABLE][1]['status']==='invalidated','Policy mismatch invalidates without ACK');
    DecisionMemory::$policy='policy-v1';$id=W::saveBatch([$a],$proofs,$contexts,$raw);
    C::table(W::BATCH_TABLE)->where('id',$id)->update(['created_at'=>date('Y-m-d H:i:s',$now-86401)]);
    check(W::nextBatch()===null&&C::$tables[W::BATCH_TABLE][2]['status']==='invalidated','24h expiry invalidates, retains payload');
    $before=count(C::$tables[W::BATCH_TABLE]);$thrown=false;
    try{W::saveBatch([$a],$proofs,$contexts,[str_repeat('x',W::MAX_PAYLOAD)]);}catch(LengthException $e){$thrown=true;}
    check($thrown&&count(C::$tables[W::BATCH_TABLE])===$before,'Oversize refused before persistence');
    check(BehaviorStore::$acks===[],'Checkpoint lifecycle never acknowledges tasks');
    resetTables();$old=date('Y-m-d H:i:s',$now-31*86400);
    for($n=0;$n<105;$n++)C::$tables[W::BATCH_TABLE][]=['id'=>(string)$n,'status'=>'complete','created_at'=>$old];
    C::$tables[W::BATCH_TABLE][]=['id'=>'keep','status'=>'pending','created_at'=>$old];
    C::$tables[W::TABLE]=[['result_state'=>'pending','created_at'=>$old],['result_state'=>'api','created_at'=>$old]];
    W::prune();check(count(C::$tables[W::BATCH_TABLE])===6&&count(C::$tables[W::TABLE])===1,'Prune bounded to 100 terminal records, preserves pending');
    Database::$config['schema_version']='22';check(!W::enabled()&&W::nextBatch()===null,'Predeployment schema gates runtime');
    echo "PASS: {$checks} analysis work checks; in-memory only\n";
}
