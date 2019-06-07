function show_new_pms() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
	if (this.readyState == 4 && this.status == 200) {
        try{
            var obj = JSON.parse(this.response);
            var obj2 = JSON.parse(obj);
            document.getElementById("receive").innerHTML = obj2.data;
        } catch(e){
            console.log("Errrorr");

        }
		}
	};
    xhttp.open("GET", "showpms", true);
	xhttp.timeout = 7000;
    xhttp.send(null);  
}


show_new_pms() 

var myVar = setInterval(show_new_pms, 7000);
