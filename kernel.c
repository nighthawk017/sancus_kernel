#include <sancus/sm_support.h>
#include <sancus_support/tsc.h>
#include <stdio.h>
#include <msp430.h>

#include "debugprinters.c"
#include "spongent_c.c"
#include "kernel.h"



// *** Shadow stack variables
static unsigned		 SM_DATA(kernel) id_stack[MAX_STACK_SIZE] ;
static void*		 SM_DATA(kernel) ep_stack[MAX_STACK_SIZE] ;
static int    		 SM_DATA(kernel) stack_size;
static void*	     SM_DATA(kernel) entry_points[TOTAL_SM];
static unsigned		 SM_DATA(kernel) sm_ids[TOTAL_SM];

// *** Local attestation variables
static int 			 SM_DATA(kernel) data_index;
static int 			 SM_DATA(kernel) sender_id;
static int 			 SM_DATA(kernel) register_id;
static void*		 SM_DATA(kernel) tag[SANCUS_TAG_SIZE];

static char		 	 SM_DATA(kernel) test_expected_hash[8] = {-103, 40, 83, 107, -126, -31, -113, 5 };

static int 			 SM_DATA(kernel) total_reg_sm;
static void*		 SM_DATA(kernel) expected_hash[HASH_SIZE/VOID_SIZE];

static int 			 SM_DATA(kernel) initialized;


static registered_sm_data SM_DATA(kernel) reg_SMs[TOTAL_SM];

static int 			 SM_DATA(kernel) reg_step;
static int 		     SM_DATA(kernel) reg_id;



/**************************************************************************************
	Removes the caller from reg_SMs array. 
*/
void SM_ENTRY(kernel) unregister() {
	sm_id caller_id = sancus_get_caller_id();
	// TODO do unprotect (requires HW change)
	int i,j;
	for(i = 0; i < total_reg_sm; i++) {
		if(reg_SMs[i].id == caller_id){
			for(j = i; j < total_reg_sm -1; j++){
				reg_SMs[j] = reg_SMs[j+1];
			}
			total_reg_sm--;
			return;
		}
	}
}


/**************************************************************************************
	Compares the expected hash with the actual hash of the SM passed as parameter. "send_hash" needs to be run before, to send the expected hash.
	Return:
		0  if the two hashes matched
		1  if the two hashes didn't match
		2  if the SM with the id passed as parameter is not registered
*/
int SM_ENTRY(kernel) verify_sm(sm_id id) {
	int i, index;
	index = -1;
	//TODO change the constant and put it in a define
	for(i = 0; i < total_reg_sm; i++) {
		if(reg_SMs[i].id == id){
			index = i;
			break;
		}
	}
	if(index == -1) {
		debug_print_int("SM with id %d not found\n", index);
		return 2;
	}

	test_expected_hash[0] = 122;
	test_expected_hash[1] = 57;
	test_expected_hash[2] = 36; 
	test_expected_hash[3] = 101;
	test_expected_hash[4] = -126; 
	test_expected_hash[5] = -45;
	test_expected_hash[6] = 95; 
	test_expected_hash[7] = 79;

	//change for condition with HASH_SIZE/VOID_SIZE
	for(i = 0; i < 8; i++) {
		char *p,*p2;
		p = (char*)reg_SMs[index].pub_hash;
		p2 = test_expected_hash;
		if(((int)*(p + i)) != ((int)*(p2 + i))) {
			debug_puts("Invalid hash");
			return 1;
		}
		// debug_print_int("%d ",(int)*(p + i));
	}
	debug_puts("Verification successful!");
	return 0;
}


/**************************************************************************************
	Computes the hash of the SM present at the index position in the reg_SMs array and stores it in the associated "hash" field.
*/
void SM_FUNC(kernel) compute_hash(int index) {
	debug_puts("Computing hash");

	unsigned int size = reg_SMs[index].pub_end_addr - reg_SMs[index].pub_start_addr - 1;
	// TODO take into consideration layout as well
	debug_print_int("### public address range %d\n", (int)size); 


	//uncommenting generateTestVectors will compute a hash on the message "Sponge + Present = Spongent"
	 // generateTestVectors();

	// uncommenting the next line computes a hash based on the public address range of the registered SM found at position index in the reg_SMs array
	// SpongentHash((BitSequence*)reg_SMs[index].pub_start_addr,(size << 3),reg_SMs[index].pub_hash);
	 
	// uncommenting the next line computes a hash based on the first 256 bits of the public address range of the registered SM found at position index in the reg_SMs array
	SpongentHash((BitSequence*)reg_SMs[index].pub_start_addr,256,(BitSequence*)reg_SMs[index].pub_hash);

	// printing the hash
	// in the case of generateTestVectors, it will print 0s (there is another printer in generateTestVectors())
	char* p ;
	p = (char*)reg_SMs[index].pub_hash;
	for(int i = 0; i < 12;i++)
		debug_print_int("%d ",(int)*(p+i));
	debug_puts(" ");

	// size = reg_SMs[index].secret_end_addr - reg_SMs[index].secret_start_addr - 1;
	// debug_print_int("### secret address range %d\n", (int)size); 


}

//TODO replace the function with sancus_get_id
sm_id SM_FUNC(kernel) get_addr_id(void * addr) {
	sm_id ret;

    asm("mov %1, r15\n\t"
        ".word 0x1386\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "m"(addr)
        : "r15");

    return ret;
}



/**************************************************************************************
	Register a protected SM in the reg_sm array.

	Return:
		0 if the registration was succesful
		1 if the address does not match the id of the caller
		2 if registration step is invalid (this would signal a bug in register_sm)
		3 if the SM is already registered
		4 if the SM doesn't have protection enabled
		5 if another register is being done at the same time
*/
int SM_ENTRY(kernel) register_sm( void *addr1,  void *addr2,  void *addr3) {
	sm_id caller_id = sancus_get_caller_id();
	if(!initialized){
		initialize_box();
		initialized = 1;
	}	

	int i;
	if(caller_id == 0) {
		debug_puts("SM not protected");
		return 4;
	}

	//TODO reactivate it (be careful to make it work for the data section as well)
	// if(get_addr_id(addr1) != caller_id) {
	// 	debug_print_int("address value: %d\n",addr1);
	// 	debug_print_int("addr1_id: %d\n",get_addr_id(addr1));
	// 	debug_puts("Invalid address");
	// 	return 1; // invalid address return code
	// }

	for(i = 0 ; i < total_reg_sm; i++) {
		if(reg_SMs[i].id == caller_id)  {
			debug_puts("SM already registered");
			return 3; // 
		}
	}

	if(reg_step == 0) {
		register_id = caller_id;
		if((get_addr_id(addr2) != caller_id) || (get_addr_id(addr1) != caller_id)) {
			debug_puts("Invalid address");
			return 1; // invalid address return code
		}
		debug_puts("\nRegistering - Step 1");
		reg_SMs[total_reg_sm].id = caller_id;
		reg_SMs[total_reg_sm].pub_start_addr = (void*)addr1;
		reg_SMs[total_reg_sm].pub_end_addr = (void*)addr2;
		reg_SMs[total_reg_sm].secret_start_addr = (void*)addr3;
		
	}
	else if(reg_step == 1){// && (caller_id == register_id)) {
		debug_puts("Registering - Step 2");
		reg_SMs[total_reg_sm].secret_end_addr = (void*)addr1;
		// debug_print_int("registered SM id: %d\n", reg_SMs[total_reg_sm].id );
		// debug_print_int("public start: %d\n",(int)reg_SMs[total_reg_sm].pub_start_addr);
		// debug_print_int("public end: %d\n",(int)reg_SMs[total_reg_sm].pub_end_addr);
		// debug_print_int("secret start: %d\n",(int)reg_SMs[total_reg_sm].secret_start_addr);
		// debug_print_int("secret end: %d\n",(int)reg_SMs[total_reg_sm].secret_end_addr);

		compute_hash(total_reg_sm);

		total_reg_sm++;
		reg_step = 0;
		return 0;
	}
	else if(caller_id != register_id) {
		debug_puts("Another register is in progress");
		return 5;
	}
	// else if(reg_step == 2) {
	// 	debug_puts("Registering - Step 3");
	// 	reg_SMs[total_reg_sm].id = caller_id;
	// 	total_reg_sm++;
	// 	reg_step = 0;
	// 	return 0;
	// }
	else {
		debug_puts("Invalid step");
		return 2; // invalid step return code
	}
	reg_step++;
	return 0;
}

/**************************************************************************************
	Function used by the caller to send the expected hash. Needs to be called several times
	Return:
		current_hash_index  if sending the hash part is successful
		-1 if another transfer from another SM is in progress
*/
int SM_ENTRY(kernel) send_hash(void *hash_part) {
	sm_id caller_id = sancus_get_caller_id();
	// if some other SM tries to transmit data when another transfer is in progress, the new transfer is ignored
	if((sender_id != caller_id) && (data_index != 0)) {
		debug_puts("Another transfer is in progress!");
		return -1; //code for "Another transfer is in progress"
	}
	else {
		if(data_index == 0) {
			sender_id = caller_id;
		}
		expected_hash[data_index++] = hash_part;
	}

	if(data_index == DATA_SIZE) 
		data_index = 0;

	return data_index; 
}




/**************************************************************************************

*/
void SM_FUNC(kernel) push(unsigned id, void *entry_point) {
	debug_puts("+ Push");	
	if(stack_size > MAX_STACK_SIZE){
		debug_puts("!!! Stack overflow!");		
		return ;
	}
	else if(sancus_get_self_id() == id){
		debug_puts("!!! Same id as the IPC!");
		return;
	}
	else if(sancus_get_id(entry_point) != id){
		debug_print_int("!!! Entry point does not belong to SM with %d! \n",id);		
		return ;
	}
	else {
		if(id == 0){
			debug_puts("!!! Warning! - entry point id is 0!");
		}
		ep_stack[stack_size] = entry_point;
		id_stack[stack_size++] = id;
	}
}

/**************************************************************************************
*/
int SM_FUNC(kernel) pop() {
	debug_puts("- Pop");	
	if(stack_size == 0) {
		debug_puts("Stack empty!");	
	}
	else {
		do {
			stack_size--;
			debug_print_int("Popping id %d \n", id_stack[stack_size]);
			debug_print_int("Popping ep %d \n", sancus_get_id(ep_stack[stack_size]));
			if(sancus_get_id(ep_stack[stack_size]) != id_stack[stack_size]){
				debug_print_int("SM %d no longer valid",id_stack[stack_size]);
			}
		}while((sancus_get_id(entry_points[stack_size]) == id_stack[stack_size]) && (stack_size > 0) );			
	}
	 return stack_size;
	
}


/**************************************************************************************
send_hash needs to be called before this function is called (in order to obtain the expected hash).

Function used for calling the callee through the use of the ismc. The kernel function requires the callee entry point,
the callee entry idx and the caller entry point. The function checks if the ids of the addresses sent as parameters match
and then verifies if the hash passed before is the same as the actual hash of the callee SM.
*/

// TODO maybe change the return type to int in order for the caller to know whether or not the actual call has succeded or if there is a problem.
void SM_ENTRY(kernel) ismc_with_verif( void *callee_entry_point, int idx, void *caller_entry_point) {

	void *ret_entry;
	sm_id caller_id =  sancus_get_caller_id();

	if(verify_sm(sancus_get_id(callee_entry_point)) == 0) {
		debug_puts("IPC");
		push(caller_id,caller_entry_point);
		
		debug_print_int("IPC caller id: %d \n",caller_id);
		
		sancus_call(callee_entry_point, idx);

		debug_puts("returned to IPC");
		int stack_level;
		stack_level = pop();
		
		return_to(ep_stack[stack_size]);		
		// TODO think of a method to reduce code duplication between the 2 versions of ismc with and without verification
	}
	else {
		debug_puts("Verification failed");
		return_to(caller_entry_point);
	}	
}


/**************************************************************************************
ismc_with_verif is used by other SMs to do inter-SM communication that doesn't verify the callee verifies the callee. This should be called after calling ismc_with_verif once.
*/
// TODO check the ids of the parameters 
// TODO change the return type in order to signal whether or not there is a problem
void SM_ENTRY(kernel) ismc_without_verif(const void *callee_entry_point, int idx, const void *caller_entry_point) {
	
	void *ret_entry;
	sm_id caller_id =  sancus_get_caller_id();
	debug_print_int("caller id is %d \n",caller_id);

	debug_puts("IPC");
	push(caller_id,(void*)caller_entry_point);
	
	debug_print_int("IPC caller id: %d \n",caller_id);
	
	sancus_call((void*)callee_entry_point, idx);

	debug_puts("returned to IPC");
	int stack_level;
	stack_level = pop();
	
	return_to(ep_stack[stack_size]);		


}
