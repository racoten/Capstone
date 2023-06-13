# Linear Search
```go
// LinearSearch performs a linear search for the target value in the slice.
// If the target value is found, the function returns the index at which the target value is found.
// If the target value is not found, the function returns -1.
func LinearSearch(slice []int, target int) int {
    for i, v := range slice {
        if v == target {
            return i
        }
    }
    return -1
}
```

# Sentinel Linear Search
```go
// SentinelLinearSearch performs a linear search for the target value in the slice using a sentinel loop.
// If the target value is found, the function returns the index at which the target value is found.
// If the target value is not found, the function returns -1.
func SentinelLinearSearch(slice []int, target int) int {
    n := len(slice)
    last := slice[n-1]
    slice[n-1] = target

    i := 0
    for slice[i] != target {
        i++
    }

    slice[n-1] = last
    if i < n-1 || slice[n-1] == target {
        return i
    }
    return -1
}
```

# Binary Search
```go
// BinarySearch performs a binary search for the target value in the slice.
// The slice must be sorted in ascending order.
// If the target value is found, the function returns the index at which the target value is found.
// If the target value is not found, the function returns -1.
func BinarySearch(slice []int, target int) int {
    low := 0
    high := len(slice) - 1

    for low <= high {
        mid := low + (high-low)/2
        if slice[mid] == target {
            return mid
        } else if slice[mid] < target {
            low = mid + 1
        } else {
            high = mid - 1
        }
    }
    return -1
}
```

# Ternary Search
```go
// TernarySearch performs a ternary search for the target value in the slice.
// The slice must be sorted in ascending order.
// If the target value is found, the function returns the index at which the target value is found.
// If the target value is not found, the function returns -1.
func TernarySearch(slice []int, target int) int {
    low := 0
    high := len(slice) - 1

    for low <= high {
        mid1 := low + (high-low)/3
        mid2 := high - (high-low)/3
        if slice[mid1] == target {
            return mid1
        } else if slice[mid2] == target {
            return mid2
        } else if slice[mid1] < target {
            low = mid1 + 1
        } else if slice[mid2] > target {
            high = mid2 - 1
        } else {
            low = mid1 + 1
            high = mid2 - 1
        }
    }
    return -1
}
```

# Jump Search
```go
// JumpSearch performs a jump search for the target value in the slice.
// The slice must be sorted in ascending order.
// If the target value is found, the function returns the index at which the target value is found.
// If the target value is not found, the function returns -1.
func JumpSearch(slice []int, target int) int {
    n := len(slice)
    step := int(math.Sqrt(float64(n)))

    prev := 0
    for slice[int(math.Min(float64(step), float64(n)))-1] < target {
        prev = step
        step += int(math.Sqrt(float64(n)))
        if prev >= n {
            return -1
        }
    }

    for i := prev; i < int(math.Min(float64(step), float64(n))); i++ {
        if slice[i] == target {
            return i
        }
    }
    return -1
}
```
