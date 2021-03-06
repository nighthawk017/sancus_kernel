#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <sancus/sm_support.h>
#include <sancus_support/tsc.h>
#include <stdio.h>
#include <msp430.h>

#include "debugprinters.h"

#define SM_ID_RET 0xffff
#define MAX_STACK_SIZE 10
#define TOTAL_SM 4
#define REG_STEPS 3 // TODO check if it's really needed

#define DATA_SIZE 4 
#define HASH_SIZE 64
#define VOID_SIZE 4

//*********************** kernel parameters

#define ISMC_COMPONENT 1 //if defined the kernel is deployed with ISMC

#define SHA2_ALG
//#define SPONGENT_ALG

//#define MICROBENCHMARKS
#define MACROBENCHMARKS

#define LOCAL_ATTESTATION_COMPONENT 1 //if defined the kernel is deployed with the local attestation component

//*********************** end of kernel parameters

DECLARE_SM(kernel,0x1234);

#define SM_GET_PUBLIC_START(sm) ({         \
    extern char __sm_##sm##_public_start;  \
    (void*)&__sm_##sm##_public_start;      \
})

#define SM_GET_PUBLIC_END(sm) ({         \
    extern char __sm_##sm##_public_end;  \
    (void*)&__sm_##sm##_public_end;      \
})

#define SM_GET_SECRET_START(sm) ({         \
    extern char __sm_##sm##_secret_start;  \
    (void*)&__sm_##sm##_secret_start;      \
})

#define SM_GET_SECRET_END(sm) ({         \
    extern char __sm_##sm##_secret_end;  \
    (void*)&__sm_##sm##_secret_end;      \
})

typedef struct {
	void* 		 pub_start_addr; 
 	void*		 pub_end_addr;
 	void*		 secret_start_addr; 
 	void*		 secret_end_addr;
 	// added 11 so that the struct has correct size
 	uint32_t* 	 pub_hash[8];
 	void* 		 aux[10];
 	char		 name;
 	sm_id        id;
 }registered_sm_data;


 #ifdef LOCAL_ATTESTATION_COMPONENT
	int SM_ENTRY(kernel)  register_sm( void *addr1,  void *addr2,  void *addr3);
	// method used for sending the has. It must be used hash_size/void_size times
	int SM_ENTRY(kernel)  send_hash(void *hash_part);
	// verify the integrity of an SM based on the id. send_hash should be used before calling this method to send the associated expected hash
	int SM_ENTRY(kernel)  verify_sm(sm_id id);
	// unregister the caller SM from reg_SMs and unprotect it (!!! would require HW change)
	void SM_ENTRY(kernel) unregister();


	void SM_ENTRY(kernel) ismc_with_verif_caller_callee( void *callee_entry_point, int idx, void *caller_entry_point);

	static void SM_FUNC(kernel) unregister_sm(int id);

	// function used for computing the hash based on the "registered_sm_data"
	static void  SM_FUNC(kernel)  compute_hash(int index);

	//TODO change return type to int in order to signal if the verification has been successful
	// ismc_with_verif is used by other SMs to do inter-SM communication that also verifies the callee
	void SM_ENTRY(kernel) ismc_with_verif(void *callee_entry_point, int id, void *caller_entry_point);

	void SM_ENTRY(kernel) hash_microbenchmark(int message_byte_size);

 #endif

//ISMC part
#define return_to(ret_entry) sancus_call(ret_entry,SM_ID_RET)

 #ifdef ISMC_COMPONENT

	static int SM_FUNC(kernel) is_registered(int id);
	// function used for pushing the caller data to the shadow call stack
	static int SM_FUNC(kernel)   push(unsigned sm_entry_point, void *entry_point);
	// function used for poping from the shadow call stack
	static int SM_FUNC(kernel)    pop();
	//helper function for ismc_call entry points
	int SM_FUNC(kernel) ismc_call(void *callee_entry_point, int idx, void *caller_entry_point, sm_id caller_id);


	// ismc_with_verif is used by other SMs to do inter-SM communication that doesn't verify the callee verifies the callee. This should be called after calling ismc_with_verif once.
	void SM_ENTRY(kernel) ismc_without_verif(const void *callee_entry_point, int id, const void *caller_entry_point);
	// method used to register an SM. It needs to be called REG_STEPS times
 #endif

	
#endif
