/*

*/

#include <sancus/sm_support.h>
#include <sancus_support/tsc.h>
#include <stdio.h>
#include <msp430.h>

#include "kernel.c"
#include "debugprinters.h"

// #include <inttypes.h>
// #include "sha2.c"


#define EXIT()                              \
    /* set CPUOFF bit in status register */ \
    asm("bis #0x210, r2");



DECLARE_SM(a , 0x1234);
DECLARE_SM(b , 0x1234);	


void SM_ENTRY(a) a_sm(void);
void SM_ENTRY(a) register_a(void);
void SM_ENTRY(b) b_sm(void);
void SM_ENTRY(b) register_b(void);

static int SM_DATA(b) ismc_id ;
static int SM_DATA(a) checked_b ;


// DECLARE_TSC_TIMER(init);
// DECLARE_TSC_TIMER(run);

void SM_ENTRY(a) register_a(void) {
	
	// sm_id  caller_id = sancus_get_self_id();
	// debug_puts("\n\n Registering...");
	// debug_print_int("address id: %d\n",sancus_get_id(a.public_start));
	debug_print_int("# a.public_start: %x\n",a.public_start);
	// debug_print_int("a.public_end : %d\n",(a.public_end-1));
	// debug_print_int("a.secret_start : %d\n",a.secret_start);
	// debug_print_int("a.secret_end : %d\n\n",a.secret_end);

	register_sm(a.public_start, a.public_end-1, a.secret_start);//b.secret_start);
	register_sm(a.secret_end,0,0);//b.secret_end);
	// debug_puts("Finished registering... ");
	// register_sm(0,0,0);
}

void SM_ENTRY(a) a_sm(void) {

	if(!checked_b){
		ismc_with_verif(SM_GET_ENTRY(b), SM_GET_ENTRY_IDX(b,b_sm),SM_GET_ENTRY(a));
		checked_b = 1;
	}
	else
		ismc_without_verif(SM_GET_ENTRY(b), SM_GET_ENTRY_IDX(b,b_sm),SM_GET_ENTRY(a));

	if(sancus_get_caller_id() != sancus_get_id(ismc_with_verif)) {
		return;
	}
}


void SM_ENTRY(b) register_b(void) {
	// sm_id  caller_id = sancus_get_self_id();
	// debug_puts("\n\n Registering...");
	debug_print_int("# b.public_start: %x\n",b.public_start);
	register_sm(b.public_start, b.public_end-1, b.secret_start); //SM_GET_SECRET_START(b));//
	register_sm(b.secret_end,0,0);// //SM_GET_SECRET_END(b)
	
	// register_sm(0,0,0);
}

void SM_ENTRY(b) b_sm(void) {
}




int main(){
	WDTCTL = WDTPW | WDTHOLD;
	  	
	sm_io_init();

	debug_puts("\n------\n[main] enabling SMs..");
	sancus_enable(&kernel);
	sancus_enable(&b);
	sancus_enable(&a);




    // debug_print_int("IPC id is: %d \n",sancus_enable(&ismc));
    // debug_print_int("A id is: %d \n",sancus_enable(&a));
    // debug_print_int("B id is: %d \n",sancus_enable(&b));
    // debug_print_int("C id is: %d \n",sancus_enable(&c)); 
    
	// debug_print_int("BitSequence size = %d \n", sizeof(BitSequence));


	
    register_a();
    // debug_puts("---");
    register_b();

	a_sm();
	a_sm();

	EXIT()

}

