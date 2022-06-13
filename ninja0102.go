package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person1 struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

func main() {

	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	http.ListenAndServe(":9090", nil)
}

func encode(w http.ResponseWriter, r *http.Request) {
	p1 := person1{
		First: "ali",
		Last:  "mali",
	}
	p2 := person1{
		First: "behnaz",
		Last:  "goli",
	}

	people := []person1{p1, p2}

	err := json.NewEncoder(w).Encode(people)
	if err != nil {
		log.Println("bad dat", err)
	}

}

func decode(w http.ResponseWriter, r *http.Request) {
	people := []person1{}

	err := json.NewDecoder(r.Body).Decode(&people)
	if err != nil {
		log.Println("bad data: ", err)

	}

	fmt.Printf("people: %v", people)
}
