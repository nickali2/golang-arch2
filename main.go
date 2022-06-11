package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type person struct{
	First string `json:"first"`
}


func main(){
	// p1 := person{
	// 	First: "John",
	// }
	// p2:= person{
	// 	First: "jenny",
	// }

	// xp := []person{p1,p2}

	// bs, er := json.Marshal(xp)
	// if er!= nil{
	// 	log.Panic(er)
	// }
	// fmt.Println(string(bs))

	// xp2:= []person{}

	// err := json.Unmarshal(bs, &xp2)
	// if err != nil{
	// 	log.Panic(err)
	// }

	// fmt.Println("back into a go data structure: ", xp2)

	http.HandleFunc("/encode", foo)
	http.HandleFunc("/decode", bar)
	http.ListenAndServe(":8080",nil)
	

}



func foo(w http.ResponseWriter, r *http.Request){
	p1 := person{
		First: "John",
	}

	err := json.NewEncoder(w).Encode(p1)
	if err != nil{
		log.Println("something bad! ", err)
	}
	
}

func bar(w http.ResponseWriter,  r*http.Request){
	
}