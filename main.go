package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type person struct{
	First string `json:"first"`
}


func main(){
	p1 := person{
		First: "John",
	}
	p2:= person{
		First: "jenny",
	}

	xp := []person{p1,p2}

	bs, er := json.Marshal(xp)
	if er!= nil{
		log.Panic(er)
	}
	fmt.Println(string(bs))
}