package main

import "fmt"

func add(a int, b int) int {
	suma := a + b
	return suma
}

func main() {
    wynik := add(5, 3)
	fmt.Println("Suma:", wynik)
    
}