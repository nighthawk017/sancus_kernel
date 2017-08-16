// *** Shadow stack variables
static unsigned		 SM_DATA(kernel) id_stack[MAX_STACK_SIZE] ;
static void*		 SM_DATA(kernel) ep_stack[MAX_STACK_SIZE] ;
static int    		 SM_DATA(kernel) stack_size;
static void*	     SM_DATA(kernel) entry_points[TOTAL_SM];
static unsigned		 SM_DATA(kernel) sm_ids[TOTAL_SM];

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