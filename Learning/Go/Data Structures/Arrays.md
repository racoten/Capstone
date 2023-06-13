# Simple Array
```go
// Create an array of integers with a length of 5.
// The array is initialized with the default value for the element type (0 for integers).
var arr [5]int

// Set the value of the first element in the array.
arr[0] = 1

// Get the value of the second element in the array.
x := arr[1]

// Iterate over the elements in the array.
for i, value := range arr {
    fmt.Printf("Index: %d, Value: %d\n", i, value)
}

// Create an array of strings with a length of 3 and initialized with values.
words := [3]string{"apple", "banana", "cherry"}

// Get the length of the array.
length := len(words)

// Check if the array is empty.
isEmpty := len(words) == 0
```

# Multi-dimensional Array
```go
// Create a 2x3 array of integers.
// The array is initialized with the default value for the element type (0 for integers).
var arr [2][3]int

// Set the value of the element at row 0, column 1.
arr[0][1] = 1

// Get the value of the element at row 1, column 2.
x := arr[1][2]

// Iterate over the elements in the array.
for i, row := range arr {
    for j, value := range row {
        fmt.Printf("Row: %d, Column: %d, Value: %d\n", i, j, value)
    }
}

// Create a 3x3 array of strings and initialize it with values.
words := [3][3]string{
    {"red", "green", "blue"},
    {"apple", "banana", "cherry"},
    {"dog", "cat", "bird"},
}

// Get the number of rows in the array.
numRows := len(words)

// Get the number of columns in the array.
numColumns := len(words[0])

// Check if the array is empty.
isEmpty := len(words) == 0
```

# Associative Array
```go
// Create a map that maps strings to integers.
// The map is initialized as empty.
var m map[string]int

// Set the value for the key "apple".
m["apple"] = 1

// Get the value for the key "banana".
x := m["banana"]

// Check if the key "cherry" is in the map.
_, ok := m["cherry"]

// Iterate over the key-value pairs in the map.
for key, value := range m {
    fmt.Printf("Key: %s, Value: %d\n", key, value)
}

// Create a map that maps strings to strings and initialize it with values.
colors := map[string]string{
    "red":   "#ff0000",
    "green": "#00ff00",
    "blue":  "#0000ff",
}

// Get the number of key-value pairs in the map.
numEntries := len(colors)

// Check if the map is empty.
isEmpty := len(colors) == 0

// Delete a key-value pair from the map.
delete(colors, "red")
```
