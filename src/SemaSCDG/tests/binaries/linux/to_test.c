#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int customFunction(int a, int b) {
    if (a > 0 && b > 0) {
        //NOT REACHED
        printf("a > 0 && b > 0");
        return a + b;
    } else if (a < 0 && b < 0) {
        //NOT REACHED
        printf("a < 0 && b < 0");
        return a - b;
    } else {
        printf("a * b");
        return a * b;
    }
}

// that reverses a string
void manipulateString(char *str) {
    int len = strlen(str);
    printf("Length of string: %d\n", len);
    printf("String before manipulation: %s\n", str);
    for (int i = 0; i < len / 2; ++i) {
        char temp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = temp;
    }
    printf("String after manipulation: %s\n", str);
}

int main() {
    int num;

    printf("Enter a positive integer: ");
    scanf("%d", &num);

    if (num <= 0) {
        // TRACE 1
        printf("Please enter a positive integer.\n");
        return 1;  // Exit with an error code
    }

    printf("Performing complex calculations based on %d...\n", num);

    int result = 0;

    for (int i = 1; i <= num; ++i) {
        printf("loop %d",i);
        if (i % 2 == 0) {
            printf("i mod 2 == 0");
            result += i;
        } else {
            printf("i mod 2 != 0");
            result -= i;
        }

        if (i > 5 && i < 10) {
            printf("i > 5 && i < 10");
            result *= 2;
        }
    }

    printf("Intermediate result after loop: %d\n", result);

    // Call the custom function with two inputs
    int x = 7;
    int y = -3;
    int customResult = customFunction(x, y);

    printf("Result of custom function with inputs %d and %d: %d\n", x, y, customResult);

    // Manipulate a string
    char myString[] = "Hello, World!";
    manipulateString(myString);

    printf("Manipulated string: %s\n", myString);

    rand();  // call a random function


    // create branching with a condition
    char *heapString = (char *)malloc(50 * sizeof(char));
    strcpy(heapString, "This is a heap string."); // Warning not present in compilation, removed by optimization
    char stackString[] = "This is a stack string.";

    if (strlen(heapString) == 42) {
        // should not execute this branch
        sprintf("Heap String: %s\n", heapString);
    } else {
        sprintf("Stack String: %s\n", stackString);
    }

    // create branching with a condition
    char *heapString2 = (char *)malloc(50 * sizeof(char));
    strcpy(heapString2, "This is a heap string too !"); // Warning not present in compilation, removed by optimization

    if(strcmp(heapString, heapString2) == 0) {
        // should not execute this branch
        printf("Heap string 1 == Heap string 2\n");
        sprintf("Heap String: %s\n", heapString);
    } else {
        printf("Heap string 1 != Heap string 2\n");
        sprintf("Heap Strings 2: %s vs Heap String 1: %s\n", heapString2, heapString);
    }

    return 0;
}
