const express = require('express');



// Constants
const PORT = 8000;
const HOST = '0.0.0.0';

// App
const app = express();




//Open Port and start listener
//---------------------------------
app.get('/', (request, response) => {
    response.send("Nothing to see here! <br> :)");

});

//-----------------------------

//Serve busybox binary
//--------------------------
app.get('/busybox', (request, response) => {
    if(request.query.arch == "ubuntux86"){
        response.sendFile(__dirname + "/busyboxbinaries/busybox-ubuntux86")
    }

});

//Serve payload
//---------------------------------
app.get('/', (request, response) => {
    response.send("Hello");
});



//////////////////

//////////////////

//////////////////







app.listen(PORT, HOST);
//cons