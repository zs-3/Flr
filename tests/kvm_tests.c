#include <stdio.h>

void run_core_tests(void);
void run_bytecode_tests(void);

int main(void) {
    printf("--- Running KVM Unit Tests ---\n");
    run_core_tests();
    run_bytecode_tests();
    printf("--- All Unit Tests Passed ---\n");
    return 0;
}
