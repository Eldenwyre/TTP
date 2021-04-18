Java.perform(function() {
    var mainAct = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');

    var onClick = mainAct.onClick
    
    onClick.implementation = function(v){
        send('onClick');

        onClick.call(this,v);

        this.cnt.value = 958;
        
        console.log(JSON.stringify(this.cnt));
    }
});