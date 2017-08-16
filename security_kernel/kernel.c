#include <sancus/sm_support.h>
#include <sancus_support/tsc.h>
#include <stdio.h>
#include <msp430.h>

#include "debugprinters.c"
//#include "spongent_c.c"
#include "kernel.h"

#include <inttypes.h>
#ifdef SHA2_ALG
	#include "sha2.c"
#endif
#ifdef SPONGENT_ALG
	#include "spongent_c.c"
#endif

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

static char		 	 SM_DATA(kernel) test_expected_hash[32] = " ";


static int 			 SM_DATA(kernel) total_reg_sm;
static uint32_t		 SM_DATA(kernel) expected_hash[4][8];
static char			 SM_DATA(kernel) sm_name[4];

static int 			 SM_DATA(kernel) initialized;


static registered_sm_data SM_DATA(kernel) reg_SMs[TOTAL_SM];
static registered_sm_data SM_DATA(kernel) aux_reg_sm; // auxiliary variable used for storing the data of the sm before registering it 

static int 			 SM_DATA(kernel) reg_step;
static int 		     SM_DATA(kernel) reg_id;

static int 			 SM_DATA(kernel) ismc_callee_id;



uint32_t SM_DATA(kernel) hash[8];

DECLARE_TSC_TIMER(registration_timer);

#ifdef MICROBENCHMARKS
	DECLARE_TSC_TIMER(microbenchmark_timer);
#endif



#ifdef ISMC_COMPONENT
	/**************************************************************************************
		The push function is used by the ISMC to push the caller SM (it's id and entry point) in the shadow call-stack. 

		Return:
			0	if the data has been pushed successfully in the shadow call-stack
			-1	if the shadow call-stack is full
			-2	if the SM sent as parameter is the kernel
			-3	if the id and entry_point sent as parameters belong to different SMs
			-4	if the SM is not protected
	*/
	int SM_FUNC(kernel) push(unsigned id, void *entry_point) {
		// debug_puts("+ Push");	
		if(stack_size > MAX_STACK_SIZE){
			debug_puts("!!! Stack overflow!");		
			return  -1; // return code for stack overflow
		}
		else if(sancus_get_self_id() == id){
			debug_puts("!!! Same id as the ISMC!");
			return -2; //return code for trying to push the kernel
		}
		else if(sancus_get_id(entry_point) != id){
			debug_print_int("!!! Entry point does not belong to SM with %d! \n",id);		
			return -3; // return code for trying to push an SM with an entry point that didn't belong to it
		}
		else {
			if(id == 0){
				debug_puts("!!! Warning! - entry point id is 0!");
				return -4; // return code for trying to push an unprotected SM
			}
			ep_stack[stack_size] = entry_point;
			id_stack[stack_size++] = id;
			return 0;
		}
	}

	/**************************************************************************************
		Pops one element from the shadow call-stack.

		Returns:
			If popping successfully it returns the new stack_size value, after popping one or more elements. It pops only one element if the element being popped has not been unprotected since it was pushed.
		If the element was unprotected it pops elements until an element is that was protected continually since it was pushed is found or the stack is empty.
			-1 	if the stack is empty
	*/
	int SM_FUNC(kernel) pop() {
		// debug_puts("- Pop");	
		if(stack_size == 0) {
			debug_puts("Stack empty!");	
			return -1; // return code for trying to pop an empty stack
		}
		else {
			do {
				stack_size--;
				// debug_print_int("Popping id %d \n", id_stack[stack_size]);
				// debug_print_int("Popping ep %d \n", sancus_get_id(ep_stack[stack_size]));
				if(sancus_get_id(ep_stack[stack_size]) != id_stack[stack_size]){
					debug_print_int("SM %d no longer valid",id_stack[stack_size]);
				}
			}while((sancus_get_id(entry_points[stack_size]) == id_stack[stack_size]) && (stack_size > 0) );			
		}
		if(stack_size == 0 && (sancus_get_id(ep_stack[stack_size]) != id_stack[stack_size]))
			return -1;
		return stack_size;	
	}


	int SM_FUNC(kernel) ismc_call(void *callee_entry_point, int idx, void *caller_entry_point, sm_id caller_id) {
		// debug_print_int("caller id is %d \n",caller_id);
		// = sancus_get_id(callee_entry_point);
		// debug_puts("ISMC");
		int ret_code = push(caller_id,(void*)caller_entry_point);
		if(ret_code < 0)
			return (-100 + ret_code );
		
		// debug_print_int("ISMC caller id: %d \n",caller_id);
		
		sancus_call((void*)callee_entry_point, idx);

		// debug_puts("returned to ISMC");
		ret_code = pop();
		if(ret_code < 0)
			return (-200 + ret_code );
	}



	/**************************************************************************************
	ismc_with_verif is used by other SMs to do inter-SM communication that doesn't verify the callee verifies the callee. This should be called after calling ismc_with_verif once.
	*/
	// TODO check the ids of the parameters 
	// TODO change the return type in order to signal whether or not there is a problem
	// TODO update push and pop to signal problems
	void SM_ENTRY(kernel) ismc_without_verif(const void *callee_entry_point, int idx, const void *caller_entry_point) {
		
		void *ret_entry;
		sm_id caller_id =  sancus_get_caller_id();
		ismc_call(callee_entry_point, idx, caller_entry_point, caller_id);
		
		return_to(ep_stack[stack_size]);		

	}
#endif



#ifdef LOCAL_ATTESTATION_COMPONENT

	/**************************************************************************************
		Removes the caller from reg_SMs array. 
	*/
	void SM_ENTRY(kernel) unregister() {
		sm_id caller_id = sancus_get_caller_id();
		// TODO do unprotect (requires HW change)
		int i,j;
		for(i = 0; i < TOTAL_SM; i++) {
			if(reg_SMs[i].id == caller_id){
					reg_SMs[i].pub_start_addr = 0;
					reg_SMs[i].pub_end_addr = 0;
					reg_SMs[i].secret_start_addr = 0;
					reg_SMs[i].secret_end_addr = 0;
					reg_SMs[i].id = 0;
					reg_SMs[i].name = 0;
				total_reg_sm--;
				return;
			}
		}
	}

	/**************************************************************************************
		Removes the caller from reg_SMs array. 
	*/
	void SM_FUNC(kernel) unregister_sm(int id) {
		sm_id caller_id = id;
		// TODO do unprotect (requires HW change)
		int i,j;
		for(i = 0; i < TOTAL_SM; i++) {
			if(reg_SMs[i].id == caller_id){
					reg_SMs[i].pub_start_addr = 0;
					reg_SMs[i].pub_end_addr = 0;
					reg_SMs[i].secret_start_addr = 0;
					reg_SMs[i].secret_end_addr = 0;
					reg_SMs[i].id = 0;
					reg_SMs[i].name = 0;

				total_reg_sm--;
				return;
			}
		}
	}

	/**************************************************************************************
		Compares the expected hash with the actual hash of the SM passed as parameter. "send_hash" needs to be run before, to send the expected hash.
		Return:
			index of corresponding expected_hash if the two hashes matched
			-1  if the two hashes didn't match
			
	*/
	int SM_ENTRY(kernel) verify_sm(sm_id id) {
		int i, index, name_index;
		index = 0;
		for(i = 0; i <= TOTAL_SM; i++) {
			if(index == 8)
				break;
			for(index = 0; index < 8; index++){
				//Dummy verification. When loaded with expected hashes use the condition commented
				if(reg_SMs[i].pub_hash[index] == reg_SMs[i].pub_hash[index]) //(reg_SMs[i].pub_hash[index] == *aux_reg_sm.pub_hash[i]){ 	
					{}
				else
					break;

			}
		}
		if(index != 8) {
			debug_puts("Invalid hash");
			return -1;
		}


		debug_puts("Verification successful!");
		return 0;
	}

	

	void* SM_DATA(kernel) message[1024]; // used for microbenchmarks

	/**************************************************************************************
		Computes the hash of the SM present at the index position in the reg_SMs array and stores it in the associated "hash" field.
	*/
	void SM_FUNC(kernel) compute_hash(int index) {
		debug_puts("Computing hash");

		//TODO check if this is specific to SHA2 or it could be used for SPONGENT as well
		unsigned int size = reg_SMs[index].pub_end_addr - reg_SMs[index].pub_start_addr - 1;
		char *p;
		debug_print_int("Size %d \n", size);

		p = (char*)reg_SMs[index].pub_start_addr;
		for(int i = 0; i < size;i++){
			message[i] = (char) *p;
			// debug_print_int("%x\n",(int)message[i]);
			p++;
		}
		message[size] = reg_SMs[index].pub_start_addr;
		message[size + 1] = reg_SMs[index].pub_end_addr;
		message[size + 2] = reg_SMs[index].secret_start_addr;
		message[size + 3] = reg_SMs[index].secret_end_addr;
		// size = size >> 3;
		
		// debug_print_int("### public address range %d\n", (int)size); 


		
		#ifdef SHA2_ALG
			SHA_2( &message, size+3, &hash[0], 0x1);
			for(int i = 0; i < 8 ; i++)
				aux_reg_sm.pub_hash[i] = hash[i];
			// for (int i=0; i<8; i++) {
		 //    	debug_print_int("0x%x",(hash[i]>>16));
		 //    	debug_print_int("%x\n",hash[i]);
		 //    }


		#endif
		#ifdef SPONGENT_ALG
			//uncommenting generateTestVectors will compute a hash on the message "Sponge + Present = Spongent"
			// generateTestVectors2();

			// uncommenting the next line computes a hash based on the public address range of the registered SM found at position index in the reg_SMs array
			// SpongentHash((BitSequence*)reg_SMs[index].pub_start_addr,(size << 3),reg_SMs[index].pub_hash);
			 
			// uncommenting the next line computes a hash based on the first 256 bits of the public address range of the registered SM found at position index in the reg_SMs array
			debug_puts("computing SPONGENT");
			size = size >> 3;
			SpongentHash((BitSequence*)message,size + 24,(BitSequence*)aux_reg_sm.pub_hash);
		#endif



		// for (int i=0; i<8; i++)
		// {
		//     debug_print_int("0x%x",(hash[i]>>16));
		//     debug_print_int("%x\n",hash[i]);
		//     if(hash[i] != reg_SMs[index].pub_hash[i])
		//     	debug_puts("Invalid hash");
		// }
		debug_puts("Finished hashing");
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

	#ifdef MICROBENCHMARKS
	void SM_ENTRY(kernel) hash_microbenchmark(int message_byte_size) {
		TSC_TIMER_START(microbenchmark_timer);		
		#ifdef SHA2_ALG
			SHA_2( &message, message_byte_size, &hash[0], 0x1);			 
		#endif
		#ifdef SPONGENT_ALG
			SpongentHash((BitSequence*)message,message_byte_size << 3,(BitSequence*)reg_SMs[index].pub_hash);
		#endif
		TSC_TIMER_END(microbenchmark_timer);

	}
	#endif

	struct SancusModule sm;

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
		TSC_TIMER_START(registration_timer);
		sm_id caller_id = sancus_get_caller_id();
		#ifdef SPONGENT_ALG
		 	if(!initialized){
		 		initialize_box();
		 		initialized = 1;
		 	}	
		#endif

		int i;


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

			aux_reg_sm.pub_start_addr = (void*)addr1;
			aux_reg_sm.pub_end_addr = (void*)addr2;
			aux_reg_sm.secret_start_addr = (void*)addr3;
			
		}
		else if(reg_step == 1){// && (caller_id == register_id)) {
			debug_puts("Registering - Step 2");

			aux_reg_sm.secret_end_addr = (void*)addr1;
			unsigned int vendor_id, i ;
			char name[16];
			i = 0;
			vendor_id = (unsigned int)addr3;
			// debug_print_int("vendor id %x\n", vendor_id);
			while((*(char*)(addr2 + i)) != '\0') {				
				name[i] = (char)(addr2 + i);
				i++;
			}

			sm.id = 0;
			sm.vendor_id = vendor_id;
			sm.name = name; 
			
			sm.public_start = aux_reg_sm.pub_start_addr;
			sm.public_end = aux_reg_sm.pub_end_addr;
			sm.secret_start = aux_reg_sm.secret_start_addr;
			sm.secret_end = aux_reg_sm.secret_end_addr;
			TSC_TIMER_END(registration_timer);
			aux_reg_sm.id = sancus_enable(&sm);			
			TSC_TIMER_START(registration_timer);

			compute_hash(total_reg_sm);
			if(verify_sm(aux_reg_sm.id)) {//reg_SMs[total_reg_sm].id )){
				debug_puts("Verification failed, hashes do not match!");
				unregister_sm(aux_reg_sm.id);
				return 6;
			}
			
			reg_SMs[total_reg_sm].pub_start_addr = aux_reg_sm.pub_start_addr;
			reg_SMs[total_reg_sm].pub_end_addr = aux_reg_sm.pub_end_addr;
			reg_SMs[total_reg_sm].secret_start_addr = aux_reg_sm.secret_start_addr;
			reg_SMs[total_reg_sm].secret_end_addr = aux_reg_sm.secret_end_addr;
			reg_SMs[total_reg_sm].id = aux_reg_sm.id;
			reg_SMs[total_reg_sm].name = name[0];


			total_reg_sm++;
			reg_step = 0;
			TSC_TIMER_END(registration_timer);
			return 0;
		}
		else if(caller_id != register_id) {
			// debug_puts("Another register is in progress");
			return 5;
		}

		else {
			debug_puts("Invalid step");
			return 2; // invalid step return code
		}
		reg_step++;
		TSC_TIMER_END(registration_timer);
		return 0;
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

		if(is_registered(sancus_get_id(callee_entry_point)) == 0) {
			ismc_callee_id = sancus_get_id(callee_entry_point); // TODO check if this is needed for anything
			ismc_call(callee_entry_point, idx, caller_entry_point, caller_id);
			// asm("pop R1");asm("pop R1");
			// debug_puts("works?");
			return_to(ep_stack[stack_size]);					
		}
		else {
			debug_puts("Verification failed");
			return_to(caller_entry_point);
		}	
	}



	/**************************************************************************************
	send_hash needs to be called before this function is called (in order to obtain the expected hash).

	Function used for calling the callee through the use of the ismc. The kernel function requires the callee entry point,
	the callee entry idx and the caller entry point. The function checks if the ids of the addresses sent as parameters match
	and then verifies if the hash passed before is the same as the actual hash of the callee SM.
	*/

	// TODO maybe change the return type to int in order for the caller to know whether or not the actual call has succeded or if there is a problem.
	void SM_ENTRY(kernel) ismc_with_verif_caller_callee( void *callee_entry_point, int idx, void *caller_entry_point) {

		void *ret_entry;
		sm_id caller_id =  sancus_get_caller_id();

		// if(verify_sm(sancus_get_id(callee_entry_point)) == 0) {
		if((is_registered(sancus_get_id(callee_entry_point))  == 0) && (is_registered(sancus_get_id(caller_entry_point)) == 0)) {
			ismc_callee_id = sancus_get_id(callee_entry_point); // TODO check if this is needed for anything
			ismc_call(callee_entry_point, idx, caller_entry_point, caller_id);


			return_to(ep_stack[stack_size]);				
		}
		else {
			debug_puts("Verification failed");
			return_to(caller_entry_point);
		}	
	}

	int SM_FUNC(kernel) is_registered(int id) {
		for(int i = 0 ; i < total_reg_sm; i++) {
			if(reg_SMs[i].id == id){
				return 0;
			}
		}
		debug_print_int("SM with id %d is not registered with the kernel\n", id);
		return 1;
	}

	int SM_ENTRY(kernel) ismc_check_caller() {
		sm_id caller_id = sancus_get_caller_id();
		if((is_registered(caller_id) == 0) && (ismc_callee_id == caller_id)) {
			return 0;
		}
		return -1;
	}

#endif


