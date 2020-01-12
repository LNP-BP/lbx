/**
```
word: number of seal types
    word: number of fields
    byte: state type (80 - amount)
    word: number of defined seal types
        word: seal type
        byte: how many (0 - any, 1 - single, FF - 1+)
    word: number of closed seal types
        word: seal type
        byte: how many (0 - any, 1 - single, FF - 1+)
```
*/