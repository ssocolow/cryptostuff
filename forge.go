package main

import (
	"fmt"
  "crypto/sha256"
  "strconv"
  "sync"
)

//goal is to have a hash that starts with four zeroes
func checkfiftymil(wgrp * sync.WaitGroup, start int) {
  same := "sms12@williams.eduforge"
  for i := start; i < start + 50000000; i++ {
    concatenated := same + strconv.Itoa(i)
    sum := sha256.Sum256([]byte(concatenated))
    if sum[0] == 0 && sum[1] == 0 && sum[2] == 0{
      fmt.Print(sum)
      fmt.Println(concatenated)
    }
  }
	//fmt.Printf("%x", sum)
  fmt.Print("Hi" + strconv.Itoa(start))
  wgrp.Done()
}

func main() {
  var wg sync.WaitGroup
  wg.Add(1)
  go checkfiftymil(&wg, 0)
  wg.Add(1)
  go checkfiftymil(&wg, 50000000)
  wg.Wait()
}

