# Simple Selection Sort
```go
// seletionSort function that takes in an array of integers
func selectionSort(arr []int) {
    // length of the array
	n := len(arr)

	// outer loop to iterte through each element in the array
	for i := 0; i < n; i++ {
		// initialize minIndex as i
		minIndex := i

		// innr loop to find the minimum element
		for j := i + 1; j < n; j++ {
			// check if the current element is less than the minimum element
			if arr[j] < arr[minIndex] {
				// update the miIndex with the current element's index
				minIndex = j
			}
		}

		// swap the elemnts at i and minIndex
		arr[i], arr[minIndex] = arr[minIndex], arr[i]
	}
}

```

# Bubble Sort
```go
// Implements bubble sort algortihm
// Loops thorugh the array multiple times
// Compares adjacent elements and swaps them if the left one is greater
// Continues until no more swaps are made
func bubbleSort(arr []int) {
	n := len(arr)

	for i := 0; i < n-1; i++ {
		swapped := false

		for j := 0; j < n-i-1; j++ {
			if arr[j] > arr[j+1] {
				arr[j], arr[j+1] = arr[j+1], arr[j] // Swap the elmments if the left one is greater
				swapped = true
			}
		}

		if !swapped { // If no swap happened, break
			break
		}
	}
}

```

# Insertion Sort
```go
// Implement insertion sort algorithm
// Loop through arr and compare each elmment to ones before it
// If an elmment is found to be less, shift it to the left
// Continue until all elmments are in the right order
func insertionSort(arr []int) {
	n := len(arr)

	for i := 1; i < n; i++ {
		key := arr[i]
		j := i - 1

		for j >= 0 && arr[j] > key {
			arr[j+1] = arr[j]
			j--
		}

		arr[j+1] = key
	}
}


```

# Merge Sort
```go
// Implements merge sort algorithm
// Recursively divide array into halves until each subarray has only 1 element
// Then merge the subarrays back together in sorted order
func mergeSort(arr []int) []int {
	if len(arr) <= 1 { // base case: return array if length is 1 or less
		return arr
	}

	mid := len(arr) / 2 // divide the array in half
	left := mergeSort(arr[:mid]) // sort the left half
	right := mergeSort(arr[mid:]) // sort the right half

	return merge(left, right) // merge the sorted halves back together
}

// Helper function to merge two sorted arrays into one sorted array
func merge(left, right []int) []int {
	result := make([]int, 0, len(left)+len(right))

	for len(left) > 0 || len(right) > 0 {
		if len(left) == 0 {
			return append(result, right...)
		}
		if len(right) == 0 {
			return append(result, left...)
		}
		if left[0] <= right[0] { // add the smaller of the first elements to the result
			result = append(result, left[0])
			left = left[1:]
		} else {
			result = append(result, right[0])
			right = right[1:]
		}
	}

	return result
}
```

# Quick Sort
```go
func quickSort(arr []int) []int {
	if len(arr) <= 1 {
		return arr
	}

	pivot := arr[0]
	left := make([]int, 0)
	right := make([]int, 0)

	for i := 1; i < len(arr); i++ {
		if arr[i] < pivot {
			left = append(left, arr[i])
		} else {
			right = append(right, arr[i])
		}
	}

	left = quickSort(left)
	right = quickSort(right)

	return append(append(left, pivot), right...)
}
```

# Heap Sort
```go
import "math"

func heapSort(arr []int) {
	n := len(arr)

	for i := n/2 - 1; i >= 0; i-- {
		heapify(arr, n, i)
	}

	for i := n - 1; i >= 0; i-- {
		arr[0], arr[i] = arr[i], arr[0]
		heapify(arr, i, 0)
	}
}

func heapify(arr []int, n, i int) {
	largest := i
	left := 2*i + 1
	right := 2*i + 2

	if left < n && arr[left] > arr[largest] {
		largest = left
	}

	if right < n && arr[right] > arr[largest] {
		largest = right
	}

	if largest != i {
		arr[i], arr[largest] = arr[largest], arr[i]
		heapify(arr, n, largest)
	}
}
```

# Radix Sort
```go
func radixSort(arr []int) {
	max := getMax(arr)

	for exp := 1; max/exp > 0; exp *= 10 {
		countSort(arr, exp)
	}
}

func countSort(arr []int, exp int) {
	n := len(arr)
	output := make([]int, n)
	count := make([]int, 10)

	for i := 0; i < n; i++ {
		count[(arr[i]/exp)%10]++
	}

	for i := 1; i < 10; i++ {
		count[i] += count[i-1]
	}

	for i := n - 1; i >= 0; i-- {
		output[count[(arr[i]/exp)%10]-1] = arr[i]
		count[(arr[i]/exp)%10]--
	}

	for i := 0; i < n; i++ {
		arr[i] = output[i]
	}
}

func getMax(arr []int) int {
	max := math.MinInt64

	for i := 0; i < len(arr); i++ {
		if arr[i] > max {
			max = arr[i]
		}
	}

	return max
}
```

# Shell Sort

Source: https://www.golangprograms.com/golang-program-for-implementation-of-shellsort.html

```go
package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {

	slice := generateSlice(20)
	fmt.Println("\n--- Unsorted --- \n\n", slice)
	shellsort(slice)
	fmt.Println("\n--- Sorted ---\n\n", slice, "\n")
}

// Generates a slice of size, size filled with random numbers
func generateSlice(size int) []int {

	slice := make([]int, size, size)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < size; i++ {
		slice[i] = rand.Intn(999) - rand.Intn(999)
	}
	return slice
}
 
func shellsort(items []int) {
    var (
        n = len(items)
        gaps = []int{1}
        k = 1
     
    )
     
    for {
        gap := element(2, k) + 1
        if gap > n-1 {
            break
        }
        gaps = append([]int{gap}, gaps...)
        k++
    }
     
    for _, gap := range gaps {
        for i := gap; i < n; i += gap {
            j := i
            for j > 0 {
                if items[j-gap] > items[j] {
                    items[j-gap], items[j] = items[j], items[j-gap]
                }
                j = j - gap
            }
        }
    }
}
 
func element(a, b int) int {
    e := 1
    for b > 0 {
        if b&1 != 0 {
            e *= a
        }
        b >>= 1
        a *= a
    }
    return e
}
```

# Pigeonhole Sort
```go
func pigeonholeSort(arr []int) {
	max := getMax(arr)
	min := getMin(arr)
	n := max - min + 1

	holes := make([]int, n)
	for i := 0; i < len(arr); i++ {
		holes[arr[i]-min]++
	}

	j := 0
	for i := 0; i < n; i++ {
		for holes[i] > 0 {
			arr[j] = i + min
			holes[i]--
			j++
		}
	}
}

func getMax(arr []int) int {
	max := math.MinInt64

	for i := 0; i < len(arr); i++ {
		if arr[i] > max {
			max = arr[i]
		}
	}

	return max
}

func getMin(arr []int) int {
	min := math.MaxInt64

	for i := 0; i < len(arr); i++ {
		if arr[i] < min {
			min = arr[i]
		}
	}

	return min
}
```

# Alphabetical Sort
```go
package main

import (
	"fmt"
	"sort"
)

func main() {
	s := []string{"Go", "Bravo", "Gopher", "Alpha", "Grin", "Delta"}
	sort.Strings(s)
	fmt.Println(s)
}
```
