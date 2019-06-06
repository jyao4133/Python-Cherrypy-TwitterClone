function show_new_broadcasts() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
        try{
            var obj = JSON.parse(this.response);
            var obj2 = JSON.parse(obj);
            document.getElementById("demo").innerHTML = obj2.data;
        } catch(e){
            console.log("Errrorr");

        }
		}
	};
    xhttp.open("GET", "showmessages", true);
    console.log(xhttp.open("GET", "showmessages", true))
	xhttp.timeout = 7000;
    xhttp.send(null); 
    
}



function show_new_users() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
        try{
            var obj = JSON.parse(this.response);
            var obj2 = JSON.parse(obj);
            document.getElementById("users").innerHTML = obj2.data;
        } catch(e){
            console.log("Errrorr");

        }
		}
	};
    xhttp.open("GET", "showusers", true);
	xhttp.timeout = 7000;
    xhttp.send(null); 
    
}
show_new_broadcasts()
show_new_users()

var myVar = setInterval(show_new_broadcasts, 7000);
var myVar2 = setInterval(show_new_users, 7000);
