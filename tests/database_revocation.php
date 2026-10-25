<?php
// Real status adapter with memory-only SQL/lock doubles; no database or native calls.
namespace WHMCS\Database {
    final class Capsule {
        public static array $tables=[],$trace=[];
        public static bool $available=true,$failTransaction=false;
        public static function table($name){return new Query($name);}
        public static function connection(){return new self;}
        public static function raw($value){return $value;}
        public static function selectOne($sql){
            self::$trace[]=$sql;
            if(str_contains($sql,'GET_LOCK'))return (object)['acquired'=>self::$available?1:0];
            if(str_contains($sql,'RELEASE_LOCK'))return (object)['released'=>1];
            throw new \RuntimeException('Unexpected SQL');
        }
        public function transaction($callback){
            self::$trace[]='begin';$before=self::$tables;
            try {
                if(self::$failTransaction)throw new \RuntimeException('fixture transaction failure');
                $result=$callback();self::$trace[]='commit';return $result;
            }catch(\Throwable $e){self::$tables=$before;self::$trace[]='rollback';throw $e;}
        }
    }
    final class Query {
        private array $conditions=[];
        public function __construct(private string $table){}
        public function where($key,$operator,$value=null){
            if(func_num_args()===2){$value=$operator;$operator='=';}
            $this->conditions[]=[$key,$operator,$value];return $this;
        }
        public function whereIn($key,$values){$this->conditions[]=[$key,'in',$values];return $this;}
        public function when($condition,$callback){if($condition)$callback($this);return $this;}
        public function lockForUpdate(){Capsule::$trace[]='row_lock';return $this;}
        private function matches($row): bool {
            foreach($this->conditions as [$key,$operator,$value]) {
                $actual=$row[$key]??null;
                $ok=match($operator){'='=>$actual==$value,'!='=>$actual!=$value,'in'=>in_array($actual,$value,true),
                    default=>throw new \RuntimeException('Unexpected predicate')};
                if(!$ok)return false;
            }
            return true;
        }
        public function first(){foreach(Capsule::$tables[$this->table]??[] as $row)if($this->matches($row))return (object)$row;return null;}
        public function update($changes){
            Capsule::$trace[]='update:'.$this->table;$count=0;
            foreach(Capsule::$tables[$this->table] as &$row)if($this->matches($row)){$row=array_replace($row,$changes);$count++;}
            return $count;
        }
    }
}
namespace AMS\Fail2Ban {
    final class Safety {public static function evidence($lines,$ip){return $lines;}}
    require dirname(__DIR__).'/lib/Database.php';
}
namespace {
    use WHMCS\Database\Capsule as C;
    use AMS\Fail2Ban\Database as D;
    $checks=0;
    function check(bool $value,string $message): void {global $checks;if(!$value)throw new RuntimeException($message);$checks++;}
    function fixture(int $schema=23,string $status='pending'): void {
        C::$available=true;C::$failTransaction=false;C::$trace=[];
        C::$tables=['mod_amssoft_fail2ban_config'=>[['key'=>'schema_version','value'=>(string)$schema]],
            'mod_amssoft_fail2ban_ai_suggestions'=>[['id'=>1,'status'=>$status,'ip'=>'198.51.100.1','source_log'=>'fixture','evidence'=>'["proof"]']],
            'mod_amssoft_fail2ban_detections'=>[['ip'=>'198.51.100.1','source_log'=>'fixture','evidence'=>'proof','validation_state'=>'validated']]];
    }
    function status(): string {return C::$tables['mod_amssoft_fail2ban_ai_suggestions'][0]['status'];}
    fixture();C::$available=false;
    check(!D::updateSuggestionStatus(1,'rejected',7),'Busy policy lock refuses rejection');
    check(status()==='pending'&&count(C::$trace)===1,'Busy lock makes no transaction/write/release');
    check(C::$trace[0]==="SELECT GET_LOCK('amsfb_policy',5) AS acquired",'Rejection lock wait bounded to five seconds');
    fixture();check(D::updateSuggestionStatus(1,'rejected',7),'Rejection succeeds');
    check(status()==='rejected','Suggestion revoked');
    check(C::$tables['mod_amssoft_fail2ban_detections'][0]['validation_state']==='rejected','Individual evidence revoked in transaction');
    check(array_slice(C::$trace,0,3)===["SELECT GET_LOCK('amsfb_policy',5) AS acquired",'begin','row_lock'],'Policy lock acquired before transaction/row lock');
    check(array_slice(C::$trace,-2)===['commit',"SELECT RELEASE_LOCK('amsfb_policy')"],'Policy lock released after commit');
    fixture();C::$failTransaction=true;
    try{D::updateSuggestionStatus(1,'rejected',7);check(false,'Exception must propagate');}
    catch(RuntimeException $e){check($e->getMessage()==='fixture transaction failure','Transaction error propagated');}
    check(status()==='pending'&&array_slice(C::$trace,-2)===['rollback',"SELECT RELEASE_LOCK('amsfb_policy')"],'Rollback releases policy lock');
    fixture(23,'rejected');check(!D::updateSuggestionStatus(1,'rejected',7),'Repeated rejection returns false');
    check(end(C::$trace)==="SELECT RELEASE_LOCK('amsfb_policy')",'Early transaction return releases lock');
    foreach(['pending','approved','auto_executed'] as $target){
        fixture(23,'rejected');check(!D::updateSuggestionStatus(1,$target,7)&&status()==='rejected','Terminal rejection cannot become '.$target);
    }
    fixture();check(D::updateSuggestionStatus(1,'auto_executed'),'Nonrevoked decision can execute');
    fixture(22);check(D::updateSuggestionStatus(1,'rejected',7),'Schema22 rejection retained');
    check(!str_contains(implode(' ',C::$trace),'GET_LOCK'),'New policy serialization limited to schema23');
    fixture();check(!D::updateSuggestionStatus(1,'invalid',7)&&C::$trace===[],'Invalid state causes no I/O');
    echo "PASS: {$checks} pure database revocation checks; no SQL/API/native calls\n";
}
