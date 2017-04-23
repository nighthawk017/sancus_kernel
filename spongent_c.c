/*
	* SPONGENT hash function - Implementation
	* This code is placed in the public domain
	* For more information, feedback or questions, please refer to our website:
	* https://sites.google.com/site/spongenthash/

*/



#include "spongent_c.h"



//############## functions added 



/* Spongent S-box */
int SM_DATA(kernel) S[16] = { 0xe, 0xd, 0xb, 0x0, 0x2, 0x1, 0x4, 0xf, 0x7, 0xa, 0x8, 0x5, 0x9, 0xc, 0x3, 0x6};


/* Spongent eight bit S-box */
int SM_DATA(kernel) sBoxLayer[256] = {
	0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6, 
	0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6, 
	0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6, 
	0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06, 
	0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26, 
	0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16, 
	0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46, 
	0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6, 
	0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76, 
	0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6, 
	0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86, 
	0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56, 
	0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96, 
	0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6, 
	0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36, 
	0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66 
};

//********************** REPLACEMENT CODE ******************************************************************************************

DECLARE_TSC_TIMER(hash_run);

void SM_FUNC(kernel) initialize_box() {
	sBoxLayer[0]   = 0xee; sBoxLayer[1]   = 0xed; sBoxLayer[2]   = 0xeb; sBoxLayer[3] = 0xe0; sBoxLayer[4] = 0xe2; sBoxLayer[5] = 0xe1; sBoxLayer[6] = 0xe4; sBoxLayer[7] = 0xef; sBoxLayer[8] = 0xe7; sBoxLayer[9] = 0xea; sBoxLayer[10] = 0xe8; sBoxLayer[11] = 0xe5; sBoxLayer[12] = 0xe9; sBoxLayer[13] = 0xec; sBoxLayer[14] = 0xe3; sBoxLayer[15] = 0xe6; 
	sBoxLayer[16]  = 0xde; sBoxLayer[17]  = 0xdd; sBoxLayer[18]  = 0xdb; sBoxLayer[19] = 0xd0; sBoxLayer[20] = 0xd2; sBoxLayer[21] = 0xd1; sBoxLayer[22] = 0xd4; sBoxLayer[23] = 0xdf; sBoxLayer[24] = 0xd7; sBoxLayer[25] = 0xda; sBoxLayer[26] = 0xd8; sBoxLayer[27] = 0xd5; sBoxLayer[28] = 0xd9; sBoxLayer[29] = 0xdc; sBoxLayer[30] = 0xd3; sBoxLayer[31] = 0xd6; 
	sBoxLayer[32]  = 0xbe; sBoxLayer[33]  = 0xbd; sBoxLayer[34]  = 0xbb; sBoxLayer[35] = 0xb0; sBoxLayer[36] = 0xb2; sBoxLayer[37] = 0xb1; sBoxLayer[38] = 0xb4; sBoxLayer[39] = 0xbf; sBoxLayer[40] = 0xb7; sBoxLayer[41] = 0xba; sBoxLayer[42] = 0xb8; sBoxLayer[43] = 0xb5; sBoxLayer[44] = 0xb9; sBoxLayer[45] = 0xbc; sBoxLayer[46] = 0xb3; sBoxLayer[47] = 0xb6; 
	sBoxLayer[48]  = 0x0e; sBoxLayer[49]  = 0x0d; sBoxLayer[50]  = 0x0b; sBoxLayer[51] = 0x00; sBoxLayer[52] = 0x02; sBoxLayer[53] = 0x01; sBoxLayer[54] = 0x04; sBoxLayer[55] = 0x0f; sBoxLayer[56] = 0x07; sBoxLayer[57] = 0x0a; sBoxLayer[58] = 0x08; sBoxLayer[59] = 0x05; sBoxLayer[60] = 0x09; sBoxLayer[61] = 0x0c; sBoxLayer[62] = 0x03; sBoxLayer[63] = 0x06; 
	sBoxLayer[64]  = 0x2e; sBoxLayer[65]  = 0x2d; sBoxLayer[66]  = 0x2b; sBoxLayer[67] = 0x20; sBoxLayer[68] = 0x22; sBoxLayer[69] = 0x21; sBoxLayer[70] = 0x24; sBoxLayer[71] = 0x2f; sBoxLayer[72] = 0x27; sBoxLayer[73] = 0x2a; sBoxLayer[74] = 0x28; sBoxLayer[75] = 0x25; sBoxLayer[76] = 0x29; sBoxLayer[77] = 0x2c; sBoxLayer[78] = 0x23; sBoxLayer[79] = 0x26; 
	sBoxLayer[80]  = 0x1e; sBoxLayer[81]  = 0x1d; sBoxLayer[82]  = 0x1b; sBoxLayer[83] = 0x10; sBoxLayer[84] = 0x12; sBoxLayer[85] = 0x11; sBoxLayer[86] = 0x14; sBoxLayer[87] = 0x1f; sBoxLayer[88] = 0x17; sBoxLayer[89] = 0x1a; sBoxLayer[90] = 0x18; sBoxLayer[91] = 0x15; sBoxLayer[92] = 0x19; sBoxLayer[93] = 0x1c; sBoxLayer[94] = 0x13; sBoxLayer[95] = 0x16; 
	sBoxLayer[96]  = 0x4e; sBoxLayer[97]  = 0x4d; sBoxLayer[98]  = 0x4b; sBoxLayer[99] = 0x40; sBoxLayer[100] = 0x42; sBoxLayer[101] = 0x41; sBoxLayer[102] = 0x44; sBoxLayer[103] = 0x4f; sBoxLayer[104] = 0x47; sBoxLayer[105] = 0x4a; sBoxLayer[106] = 0x48; sBoxLayer[107] = 0x45; sBoxLayer[108] = 0x49; sBoxLayer[109] = 0x4c; sBoxLayer[110] = 0x43; sBoxLayer[111] = 0x46; 
	sBoxLayer[112] = 0xfe; sBoxLayer[113] = 0xfd; sBoxLayer[114] = 0xfb; sBoxLayer[115] = 0xf0; sBoxLayer[116] = 0xf2; sBoxLayer[117] = 0xf1; sBoxLayer[118] = 0xf4; sBoxLayer[119] = 0xff; sBoxLayer[120] = 0xf7; sBoxLayer[121] = 0xfa; sBoxLayer[122] = 0xf8; sBoxLayer[123] = 0xf5; sBoxLayer[124] = 0xf9; sBoxLayer[125] = 0xfc; sBoxLayer[126] = 0xf3; sBoxLayer[127] = 0xf6; 
	sBoxLayer[128] = 0x7e; sBoxLayer[129] = 0x7d; sBoxLayer[130] = 0x7b; sBoxLayer[131] = 0x70; sBoxLayer[132] = 0x72; sBoxLayer[133] = 0x71; sBoxLayer[134] = 0x74; sBoxLayer[135] = 0x7f; sBoxLayer[136] = 0x77; sBoxLayer[137] = 0x7a; sBoxLayer[138] = 0x78; sBoxLayer[139] = 0x75; sBoxLayer[140] = 0x79; sBoxLayer[141] = 0x7c; sBoxLayer[142] = 0x73; sBoxLayer[143] = 0x76; 
	sBoxLayer[144] = 0xae; sBoxLayer[145] = 0xad; sBoxLayer[146] = 0xab; sBoxLayer[147] = 0xa0; sBoxLayer[148] = 0xa2; sBoxLayer[149] = 0xa1; sBoxLayer[150] = 0xa4; sBoxLayer[151] = 0xaf; sBoxLayer[152] = 0xa7; sBoxLayer[153] = 0xaa; sBoxLayer[154] = 0xa8; sBoxLayer[155] = 0xa5; sBoxLayer[156] = 0xa9; sBoxLayer[157] = 0xac; sBoxLayer[158] = 0xa3; sBoxLayer[159] = 0xa6; 
	sBoxLayer[160] = 0x8e; sBoxLayer[161] = 0x8d; sBoxLayer[162] = 0x8b; sBoxLayer[163] = 0x80; sBoxLayer[164] = 0x82; sBoxLayer[165] = 0x81; sBoxLayer[166] = 0x84; sBoxLayer[167] = 0x8f; sBoxLayer[168] = 0x87; sBoxLayer[169] = 0x8a; sBoxLayer[170] = 0x88; sBoxLayer[171] = 0x85; sBoxLayer[172] = 0x89; sBoxLayer[173] = 0x8c; sBoxLayer[174] = 0x83; sBoxLayer[175] = 0x86; 
	sBoxLayer[176] = 0x5e; sBoxLayer[177] = 0x5d; sBoxLayer[178] = 0x5b; sBoxLayer[179] = 0x50; sBoxLayer[180] = 0x52; sBoxLayer[181] = 0x51; sBoxLayer[182] = 0x54; sBoxLayer[183] = 0x5f; sBoxLayer[184] = 0x57; sBoxLayer[185] = 0x5a; sBoxLayer[186] = 0x58; sBoxLayer[187] = 0x55; sBoxLayer[188] = 0x59; sBoxLayer[189] = 0x5c; sBoxLayer[190] = 0x53; sBoxLayer[191] = 0x56; 
	sBoxLayer[192] = 0x9e; sBoxLayer[193] = 0x9d; sBoxLayer[194] = 0x9b; sBoxLayer[195] = 0x90; sBoxLayer[196] = 0x92; sBoxLayer[197] = 0x91; sBoxLayer[198] = 0x94; sBoxLayer[199] = 0x9f; sBoxLayer[200] = 0x97; sBoxLayer[201] = 0x9a; sBoxLayer[202] = 0x98; sBoxLayer[203] = 0x95; sBoxLayer[204] = 0x99; sBoxLayer[205] = 0x9c; sBoxLayer[206] = 0x93; sBoxLayer[207] = 0x96; 
	sBoxLayer[208] = 0xce; sBoxLayer[209] = 0xcd; sBoxLayer[210] = 0xcb; sBoxLayer[211] = 0xc0; sBoxLayer[212] = 0xc2; sBoxLayer[213] = 0xc1; sBoxLayer[214] = 0xc4; sBoxLayer[215] = 0xcf; sBoxLayer[216] = 0xc7; sBoxLayer[217] = 0xca; sBoxLayer[218] = 0xc8; sBoxLayer[219] = 0xc5; sBoxLayer[220] = 0xc9; sBoxLayer[221] = 0xcc; sBoxLayer[222] = 0xc3; sBoxLayer[223] = 0xc6; 
	sBoxLayer[224] = 0x3e; sBoxLayer[225] = 0x3d; sBoxLayer[226] = 0x3b; sBoxLayer[227] = 0x30; sBoxLayer[228] = 0x32; sBoxLayer[229] = 0x31; sBoxLayer[230] = 0x34; sBoxLayer[231] = 0x3f; sBoxLayer[232] = 0x37; sBoxLayer[233] = 0x3a; sBoxLayer[234] = 0x38; sBoxLayer[235] = 0x35; sBoxLayer[236] = 0x39; sBoxLayer[237] = 0x3c; sBoxLayer[238] = 0x33; sBoxLayer[239] = 0x36; 
	sBoxLayer[240] = 0x6e; sBoxLayer[241] = 0x6d; sBoxLayer[242] = 0x6b; sBoxLayer[243] = 0x60; sBoxLayer[244] = 0x62; sBoxLayer[245] = 0x61; sBoxLayer[246] = 0x64; sBoxLayer[247] = 0x6f; sBoxLayer[248] = 0x67; sBoxLayer[249] = 0x6a; sBoxLayer[250] = 0x68; sBoxLayer[251] = 0x65; sBoxLayer[252] = 0x69; sBoxLayer[253] = 0x6c; sBoxLayer[254] = 0x63; sBoxLayer[255] = 0x66; 

}

// int multiply2(int a, int b) {
// 	return a*b;
// }

// int SM_FUNC(kernel) multiply(int a, int b) {
// 	// if((a < 0) || (b < 0))
// 	// 	debug_puts("smaller");

// 	int result = 0;
// 	int i = 0;
// 	while(a != 0) {
// 		if(a % 2){
// 			result += b;
// 		}
// 		a = a >> 1;
// 		b = b << 1;
// 		i++;
// 		//TODO change to to a constant
// 		if(i == 32)
// 			break;
// 	}
// 	return result;
// }

// int modulo2(int a, int b) {
// 	return a%b;
// }

// int SM_FUNC(kernel) modulo(int a, int b) {

// 	if(a < b)
// 		return a;
// 	int result = a;
// 	while(result > b){
// 		result = result - b;
// 	}
// 	return result;
// }

 void * SM_FUNC(kernel) c_memcpy(void *dst, const void *src, size_t len)
 {
         size_t i;
 
         
          // * memcpy does not support overlapping buffers, so always do it
          // * forwards. (Don't change this without adjusting memmove.)
          // *
          // * For speedy copying, optimize the common case where both pointers
          // * and the length are word-aligned, and copy word-at-a-time instead
          // * of byte-at-a-time. Otherwise, copy by bytes.
          // *
          // * The alignment logic below should be portable. We rely on
          // * the compiler to be reasonably intelligent about optimizing
          // * the divides and modulos out. Fortunately, it is.
          
         if ((uintptr_t)dst % sizeof(long) == 0 &&
             (uintptr_t)src % sizeof(long) == 0 &&
             len % sizeof(long) == 0) {
                 long *d = dst;
                 const long *s = src;
 
                 for (i=0; i<len/sizeof(long); i++) {
                         d[i] = s[i];
                 }
         }
         else {
                 char *d = dst;
                 const char *s = src;
 
                 for (i=0; i<len; i++) {
                         d[i] = s[i];
                 }
         }
 
         return dst;
 }

// void * SM_FUNC(kernel) c_memcpy(void *dest, void *src, size_t n)
// {
//    // Typecast src and dest addresses to (char *)
//    char *csrc = (char *)src;
//    char *cdest = (char *)dest;
 
//    // Copy contents of src[] to dest[]
//    for (int i=0; i<n; i++)
//        cdest[i] = csrc[i];
//    return dest;
// }


void SM_FUNC(kernel) c_copy_n(void *first, int count, void* result) {
 	c_memcpy(result,first,count); //TODO check if correct
}

long long  c_min(long long a, long long b) {
	if(a > b)
		return b;
	else
		return a;

}

void SM_FUNC(kernel) *c_memset(void *s, int c, size_t n)
{
    unsigned char* p=s;
    while(n--)
        *p++ = (unsigned char)c;
    return s;
}

void SM_FUNC(kernel) c_fill_n(BitSequence *start, int size, int value) {
	c_memset(start, value, size);	
}

/* check if this is correct and makes any sense */
int  SM_FUNC(kernel) c_equal(BitSequence* start, BitSequence* stop, BitSequence* expectedValue) {
	BitSequence* expected_value_iter = expectedValue;
	BitSequence* iter = start;
	if(start == stop) {
		if(start == expectedValue)
			return 1;
		else 
			return 0;
	}
	while(start != stop) {
		if(iter != expected_value_iter)
			return 0;
		iter = iter + 1;
		expected_value_iter = expected_value_iter + 1;
	}
	return 1;
}

// //TODO Fix this 
// void* SM_FUNC(kernel) c_end(void* p) {
// 	return p;
// }
// //ToDo Fix this
// void* SM_FUNC(kernel) c_begin(void* p) {
// 	return p;
// }


//************************************************************************************************************************************

//###################



//--------------------------------------------------------------------------------------------

bit16 SM_FUNC(kernel) lCounter(bit16 lfsr)
{
	switch( version ) {
		case     88808:
			lfsr = (lfsr << 1) | (((0x20 & lfsr) >> 5) ^ ((0x10 & lfsr) >> 4));
			lfsr &= 0x3f;
			break;
		case   1281288:
		case  16016016:
		case  16016080:
		case  22422416:
			lfsr = (lfsr << 1) | (((0x40 & lfsr) >> 6) ^ ((0x20 & lfsr) >> 5));
			lfsr &= 0x7f; 
			break;
		case   8817688:
		case 128256128:
		case 160320160:
		case 224224112:
		case  25625616:
		case 256256128:
			lfsr = (lfsr << 1) | (((0x80 & lfsr) >> 7) ^ ((0x08 & lfsr) >> 3) ^ ((0x04 & lfsr) >> 2) ^ ((0x02 & lfsr) >> 1));
			lfsr &= 0xff; 
			break;
		case 224448224:
		case 256512256:
			lfsr = (lfsr << 1) | (((0x100 & lfsr) >> 8) ^ ((0x08 & lfsr) >> 3));
			lfsr &= 0x1ff;
			break;
		default :
			// printf("ErrorCounter\n");
			// debug_puts("ErrorCounter");
			break;
	}
	return lfsr;
}

//--------------------------------------------------------------------------------------------

bit16 SM_FUNC(kernel) retnuoCl(bit16 lfsr)
{
	switch(version)
	{
		case     88808:
		case   8817688:
		case   1281288:
		case 128256128:
		case  16016016:
		case  16016080:
		case 160320160:
		case  22422416:
		case 224224112:
		case  25625616:
		case 256256128:
			lfsr = ( ((lfsr & 0x01) <<7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3) | ((lfsr & 0x08) << 1) | ((lfsr & 0x10) >> 1) | ((lfsr & 0x20) >> 3) | ((lfsr & 0x40) >> 5) | ((lfsr & 0x80) >> 7) );		
			lfsr <<= 8;
			break;
		case 224448224:	
		case 256512256:	
			lfsr = ( ((lfsr & 0x01) <<8) | ((lfsr & 0x02) << 6) | ((lfsr & 0x04) << 4) | ((lfsr & 0x08) << 2) | ((lfsr & 0x10) << 0) | ((lfsr & 0x20) >> 2) | ((lfsr & 0x40) >> 4) | ((lfsr & 0x80) >> 6) | ((lfsr & 0x100) >> 8) ); 
			lfsr <<= 7;
			break;
		default :
			// debug_puts("ErrorInverseCounter\n");
			// printf("ErrorInverseCounter\n");
			break;			
	}	
	
	return lfsr;
}

//--------------------------------------------------------------------------------------------

int SM_FUNC(kernel) Pi(int i)
{
	if (i != nBits-1) {
		return (i*nBits/4)%(nBits-1);
	}
	else
		return nBits-1;
}



//--------------------------------------------------------------------------------------------


void SM_FUNC(kernel) pLayer(hashState *state)
{
	int	i, j, PermutedBitNo;
	bit8	tmp[nSBox], x, y;
	
	for(i = 0; i < nSBox; i++) tmp[i] = 0;
	
	for(i = 0; i < nSBox; i++){
		for(j = 0; j < 8; j++){ 
			x			= GET_BIT(state->value[i],j);
			PermutedBitNo	= Pi(8*i+j);
			y			= PermutedBitNo/8;
			tmp[y]		^= x << (PermutedBitNo - 8*y);
		}
	}	
	c_memcpy(state->value, tmp, nSBox);
}

//--------------------------------------------------------------------------------------------

void SM_FUNC(kernel) Permute(hashState *state)
{
	bit16	i, j, IV, INV_IV;
	
	switch(version)
	{
		case     88808:	IV = 0x05;	break;
		case   8817688:	IV = 0xC6;	break;
		case   1281288:	IV = 0x7A;	break;
		case 128256128:	IV = 0xFB;	break;
		case  16016016:	IV = 0x45;	break;
		case  16016080:	IV = 0x01;	break;
		case 160320160:	IV = 0xA7;	break;
		case  22422416:	IV = 0x01;	break;
		case 224224112:	IV = 0x52;	break;
		case 224448224:	IV = 0x105; break;
		case  25625616:	IV = 0x9e;	break;
		case 256256128:	IV = 0xfb;	break;
		case 256512256:	IV = 0x015;	break;
	}
	
	for(i = 0; i < nRounds; i++){
		/* Add counter values */
		state->value[0]			^= IV & 0xFF;
		state->value[1]			^= (IV >> 8) & 0xFF;
		INV_IV	= retnuoCl(IV);
		state->value[nSBox-1]	^= (INV_IV >> 8) & 0xFF;;
		state->value[nSBox-2]	^= INV_IV & 0xFF;		
		IV	= lCounter(IV);
		
		/* sBoxLayer layer */
		for ( j=0; j < nSBox; j++)	
			state->value[j] =  sBoxLayer[state->value[j]];

		/* pLayer */
		pLayer(state);

	}

}

//--------------------------------------------------------------------------------------------

HashReturn SM_FUNC(kernel) Init(hashState *state, BitSequence *hashval)// = nullptr)
{
	/* check hashsize and initialize accordingly */
// 	switch( hashsize )
// 	{
// 		case 88:		break;
// 		case 128:		break;
// 		case 160:		break;
// 		case 224:		break;
// 		case 256:		break;
//
// 		default:
// 			return BAD_HASHBITLEN;
// 	}
	

	c_memset(state->value, 0, nSBox);	
	state->hashbitlen = 0;
	state->remainingbitlen = 0;

    if (hashval != NULL) //nullptr)
        c_memset(hashval, 0, hashsize/8);
	
	return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn SM_FUNC(kernel) Absorb(hashState *state)
{
	//debug_print_int("R_SizeInBytes = %d \n",R_SizeInBytes);
	int i;
	for(i = 0; i < R_SizeInBytes; i++)	
		state->value[i] ^= state->messageblock[i];
 	Permute(state);
	
	return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn SM_FUNC(kernel) Squeeze(hashState *state)
{
	c_memcpy(state->messageblock, state->value, R_SizeInBytes);
	
	Permute(state);
	
	return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn SM_FUNC(kernel) Pad(hashState *state)			
{
        int byteind = state->remainingbitlen/8; /* byte index of remaining byte */
        int bitpos = state->remainingbitlen%8; /* bit position in last byte */
        
        /* make unoccupied bits 0 */
        if(bitpos)
            state->messageblock[byteind] &= 0xff >> (8 - bitpos);

        /* add single 1-bit */
        if(bitpos)
            state->messageblock[byteind] |= 0x01 << bitpos;
        else
            state->messageblock[byteind] = 0x01;
        
        /* add 0-bits until we have rate bits */
        while(byteind!=R_SizeInBytes)
        {
                byteind++;
                state->messageblock[byteind] = 0;
        }
        return SUCCESS;
}

//--------------------------------------------------------------------------------------------



HashReturn SM_FUNC(kernel) SpongentHash(const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	TSC_TIMER_START(hash_run);
	hashState  state;
	HashReturn res;

	/* initialize */
	res = Init(&state, hashval); 	
	if(res != SUCCESS)
		return res;	
	TSC_TIMER_END(hash_run);
	TSC_TIMER_START(hash_run);
	/* Absorb available message blocks */
	
	while(databitlen >= rate)
	{
		c_memcpy(state.messageblock, data, R_SizeInBytes);	

		// TSC_TIMER_START(hash_run);		
		Absorb(&state);
		// TSC_TIMER_END(hash_run);	
		databitlen -= rate;
		data += R_SizeInBytes;
	}
	
	
	/* Pad the remaining bits before absorbing */
	if(databitlen>0){
		c_memcpy(state.messageblock, data, databitlen/8 + (databitlen%8?1:0));
		state.remainingbitlen = databitlen;
		}
	else if(databitlen==0){
		c_memset(state.messageblock, 0, R_SizeInBytes);
		state.remainingbitlen = databitlen;
		}
	Pad(&state);

	Absorb(&state);
	state.hashbitlen += rate;
	TSC_TIMER_END(hash_run);
	
	TSC_TIMER_START(hash_run);
	/* Squeeze data blocks */		
	while(state.hashbitlen < hashsize)
	{
		Squeeze(&state);
		c_memcpy(hashval, state.messageblock, R_SizeInBytes);
		state.hashbitlen += rate;
		hashval += R_SizeInBytes;
	}	

	c_memcpy(hashval, state.value, R_SizeInBytes);
	hashval += R_SizeInBytes;
	
	TSC_TIMER_END(hash_run);
	
	return SUCCESS;
}

HashReturn SM_FUNC(kernel) Duplexing(hashState* state,
                     BitSequence* block,
                     DataLength blockBitLength,
                     BitSequence* out,
                     DataLength outBitsLength)

{

    c_copy_n(block, BITS_TO_BYTES(blockBitLength), state->messageblock);
    state->remainingbitlen = blockBitLength;
    HashReturn ret = Pad(state);

    if (ret != SUCCESS)
        return ret;

    ret = Absorb(state);

    if (ret != SUCCESS)
        return ret;

    if (out != NULL)
    	c_copy_n(state->value, outBitsLength / 8, out);

    return SUCCESS;
}

// HashReturn SpongentWrap(const BitSequence* key,
//                         const BitSequence* ad, DataLength adBitLength,
//                         const BitSequence* input, DataLength bitLength,
//                         BitSequence* output,
//                         BitSequence* tag,
//                         // bool unwrap)
//                         int unwrap)
// {
//     if (adBitLength % 8 != 0 || bitLength % 8 != 0)
//     {
//         // fprintf(stderr, "Messages containing partial bytes not supported\n");
//         return FAIL;
//     }

//     hashState state;
//     HashReturn ret = Init(&state, NULL);

//     if (ret != SUCCESS)
//         return ret;

//     BitSequence block[R_SizeInBytes];
//     BitSequence duplexOut[R_SizeInBytes];
//     DataLength bitsLeft = KEY_SIZE;

//     while (bitsLeft > SW_RATE)
//     {
//         // std::copy_n(key, SW_RATE_BYTES, block);
//         c_copy_n(key, SW_RATE_BYTES, block);
//         block[SW_RATE_BYTES] = 0x01;
//         ret = Duplexing(&state, block, SW_RATE + 1, NULL, SW_RATE);

//         if (ret != SUCCESS)
//             return ret;

//         bitsLeft -= SW_RATE;
//         key += SW_RATE_BYTES;
//     }

//     // std::copy_n(key, bitsLeft / 8, block);
//     c_copy_n(key, bitsLeft / 8, block);
//     block[bitsLeft / 8] = 0x00;
//     ret = Duplexing(&state, block, bitsLeft + 1, NULL, SW_RATE);

//     if (ret != SUCCESS)
//         return ret;

//     bitsLeft = adBitLength;

//     while (bitsLeft > SW_RATE)
//     {
//     	c_copy_n(ad, SW_RATE_BYTES, block);
//         // std::copy_n(ad, SW_RATE_BYTES, block);
//         block[SW_RATE_BYTES] = 0x00;
//         ret = Duplexing(&state, block, SW_RATE + 1, NULL, SW_RATE);

//         if (ret != SUCCESS)
//             return ret;

//         bitsLeft -= SW_RATE;
//         ad += SW_RATE_BYTES;
//     }

//     c_copy_n(ad, bitsLeft / 8, block);
//     // std::copy_n(ad, bitsLeft / 8, block);
//     block[bitsLeft / 8] = 0x01;
//     ret = Duplexing(&state, block, bitsLeft + 1, duplexOut, SW_RATE);

//     if (ret != SUCCESS)
//         return ret;

//     DataLength firstBlockLength =
//     	c_min(bitLength, (DataLength)SW_RATE) / 8;
//         // std::min(bitLength, (DataLength)SW_RATE) / 8;

//     for (DataLength i = 0; i < firstBlockLength; i++)
//         output[i] = input[i] ^ duplexOut[i];

//     bitsLeft = bitLength;

//     while (bitsLeft > SW_RATE)
//     {
//     	c_copy_n(unwrap ? output : input, SW_RATE_BYTES, block);
//         // std::copy_n(unwrap ? output : input, SW_RATE_BYTES, block);
//         block[SW_RATE_BYTES] = 0x01;
//         HashReturn ret = Duplexing(&state, block, SW_RATE + 1, duplexOut, SW_RATE);

//         if (ret != SUCCESS)
//             return ret;

//         bitsLeft -= SW_RATE;
//         input += SW_RATE_BYTES;
//         output += SW_RATE_BYTES;

//         DataLength blockLength = c_min(bitsLeft, (DataLength)SW_RATE) / 8;
//         						// std::min(bitsLeft, (DataLength)SW_RATE) / 8;

//         for (DataLength i = 0; i < blockLength; i++)
//             output[i] = input[i] ^ duplexOut[i];
//     }

//     c_copy_n(unwrap ? output : input, bitsLeft / 8, block);
//     // std::copy_n(unwrap ? output : input, bitsLeft / 8, block);
//     block[bitsLeft / 8] = 0x00;
//     ret = Duplexing(&state, block, bitsLeft + 1,
//                     tag, c_min((DataLength)TAG_SIZE, (DataLength)SW_RATE));
//                     // std::min((DataLength)TAG_SIZE, (DataLength)SW_RATE));

//     if (ret != SUCCESS)
//         return ret;

//     DataLength tagBitsDone = SW_RATE;
//     tag += SW_RATE_BYTES;
//     c_fill_n(block, sizeof(block), 0x00);
//     // std::fill_n(block, sizeof(block), 0x00);

//     while (tagBitsDone < TAG_SIZE)
//     {
//         ret = Duplexing(&state, block, 0, tag,
//         				c_min(TAG_SIZE - tagBitsDone, (DataLength)SW_RATE));
//                         // std::min(TAG_SIZE - tagBitsDone, (DataLength)SW_RATE));

//         if (ret != SUCCESS)
//             return ret;

//         tagBitsDone += SW_RATE;
//         tag += SW_RATE_BYTES;
//     }

//     return SUCCESS;
// }

// HashReturn SpongentUnwrap(const BitSequence* key,
//                           const BitSequence* ad, DataLength adBitLength,
//                           const BitSequence* input, DataLength bitLength,
//                           BitSequence* output,
//                           const BitSequence* expectedTag)
// {
//     BitSequence tag[TAG_SIZE_BYTES];
//     HashReturn ret = SpongentWrap(key,
//                                   ad, adBitLength,
//                                   input, bitLength,
//                                   output, tag, 1);// /*unwrap=*/true);

//     if (ret != SUCCESS)
//         return ret;

//     if (!c_equal(c_begin(tag), c_end(tag), expectedTag)) //std::equal(std::begin(tag), std::end(tag), expectedTag))
//         return BAD_TAG;

//     return SUCCESS;
// }

// HashReturn SpongentMac(const BitSequence* key,
//                        const BitSequence* input, DataLength bitLength,
//                        BitSequence* mac)
// {
//     return SpongentWrap(key, input, bitLength, NULL, 0, NULL, mac,0);//nullptr, 0, nullptr, mac);
// }

//--------------------------------------------------------------------------------------------
  BitSequence message[256] = "Sponge + Present = Spongent";


void SM_ENTRY(kernel) generateTestVectors(void)
{
	int i;
	BitSequence hashval[hashsize/8]={0};

//	BitSequence message[256] = {'S', 'p', 'o', 'n', 'g', 'e', ' ', '+', ' ', 
//								'P', 'r', 'e', 's', 'e', 'n', 't', ' ', '=', ' ', 
//								'S', 'p', 'o', 'n', 'g', 'e', 'n', 't'};   	

//	BitSequence message[256] = {0x53, 0x70, 0x6F, 0x6E, 0x67, 0x65, 0x20, 0x2B, 
//								0x20, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6E, 0x74, 
//								0x20, 0x3D, 0x20, 0x53, 0x70, 0x6F, 0x6E, 0x67, 0x65, 0x6E, 0x74};
	
	DataLength databitlen = 216;		

	initialize_box();

	SpongentHash(message,databitlen,hashval);
	//print hash
	debug_puts("\nHash\t\t:");
	for(i=0; i<hashsize/8; i++)
		debug_print_int("%d",hashval[i]);
	debug_puts("\n");		
}

