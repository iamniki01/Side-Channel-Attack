/*

author: RAKSHIT AR
	NIKHIL GOWDA S
        AHMED


*/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define BLOCKSIZE  256
#define R_BLOCKSIZE  9
#define MAX_VAL 65536
#define DATA_BITS 16
#define ROUNDS 12


/* run this program using the console pauser or add your own getch, system("pause") or input loop */

typedef unsigned char   byte;

//Declare Functions
void Ceasar_Shift(unsigned int k, int Display);//Rotate
void Ceasar_Re_Shift(unsigned int k, int Display);//Re_Rotate
void Ceasar_Shift_Var(int Display);
void Ceasar_Re_Shift_Var(int Display);
void Complement(int Display);
void Re_Complement(int Display);
void Reflect(int Display);
void Re_Reflect(int Display);
void Substitution(int Display);
void Re_Substitution(int Display);
void Shuffle(int Display);
void Re_Shuffle(int Display);
void XOR_Key(int Display);
void Re_XOR_Key(int Display);
void Test_Distribution_of_Bytes(unsigned int X[], unsigned int Size);
void Diffusion_XOR(int Display);
void Re_Diffusion_XOR(int Display);
void Init_RNG(void);
byte Get_RandomByte(void);
void Encrytion_MasterKey(void);
void Masking_kEY(void);
void UnMasking_KEY(void);
void Data_Complement(void);
void Data_Re_Complement(void);
void Key_16bits(void);
void Sub_key_gen(void);
void NoOperation_Reduced(void);


unsigned int start_val = 123;
unsigned int Rounds = ROUNDS;
int i = 0;
int j = 0;
unsigned int sv[BLOCKSIZE];//Start Values
unsigned int enc[BLOCKSIZE];//Encrypted Values
unsigned int dec[BLOCKSIZE];//Decrypted Values
unsigned int enc_Save[BLOCKSIZE];//Encrypted Values
unsigned int RandomNumbers[BLOCKSIZE];
unsigned int RandomRNG_1 = 0;
unsigned int RandomRNG_2 = 0;
int Count_Equal = 0;
int Count_Equal_Bits = 0;
unsigned int BitsBuffer = 0;
double Equal_Bits_Percent = 0;
unsigned int key[ROUNDS][BLOCKSIZE];
unsigned int master_key[BLOCKSIZE];
unsigned int mkey_16bit[BLOCKSIZE];
unsigned int msk_master_key[BLOCKSIZE];
unsigned int unmsk_master_key[BLOCKSIZE];
unsigned int x_Nop = 0;
unsigned int i_Nop = 0;



	
unsigned int key_raw[BLOCKSIZE] = {
152, 55, 7, 8, 143, 239, 20, 215, 221, 151, 100, 179, 57, 208, 71, 13, 46, 50, 244, 44, 105, 59, 89, 109, 172, 47, 214, 24, 178, 169,  
114, 177, 41, 18, 200, 148, 157, 30, 110, 231, 26, 188, 228, 236, 25, 79, 58, 74, 6, 139, 240, 11, 12, 10, 81, 102, 97, 160, 250, 248,  
126, 83, 223, 156, 16, 181, 72, 186, 112, 34, 106, 19, 235, 9, 201, 82, 232, 142, 170, 98, 191, 125, 3, 80, 43, 27, 161, 198, 84, 122,  
117, 36, 132, 61, 40, 182, 247, 253, 28, 99, 204, 17, 167, 159, 85, 205, 77, 66, 202, 2, 162, 4, 37, 171, 33, 189, 249, 184, 113, 76,  
15, 155, 118, 138, 70, 87, 23, 51, 96, 150, 222, 145, 52, 60, 116, 254, 163, 141, 94, 241, 22, 73, 153, 234, 119, 185, 180, 31, 14, 225,  
245, 62, 53, 95, 217, 64, 242, 218, 197, 121, 219, 69, 136, 68, 140, 128, 224, 45, 243, 173, 108, 88, 1, 154, 103, 229, 196, 216, 86, 252,  
158, 127, 207, 233, 176, 251, 238, 209, 32, 165, 210, 78, 175, 164, 134, 213, 93, 65, 226, 144, 29, 107, 38, 115, 48, 149, 227, 130, 133, 101,  
0, 137, 120, 21, 123, 187, 255, 42, 168, 237, 5, 104, 56, 193, 54, 63, 111, 206, 49, 199, 129, 203, 212, 91, 135, 35, 174, 124, 220, 195,  
92, 146, 230, 147, 211, 67, 166, 90, 194, 192, 246, 190, 131, 39, 75, 183  
};

unsigned int Substitution_Table[BLOCKSIZE] = {  
89, 38, 232, 96, 180, 1, 68, 111, 40, 72, 12, 182, 212, 197, 181, 104, 112, 92, 164, 29, 152, 219, 8, 134, 32, 222, 129, 148, 4, 11,  
158, 124, 185, 176, 191, 5, 163, 37, 202, 236, 210, 9, 91, 84, 19, 234, 127, 95, 28, 58, 150, 87, 55, 192, 54, 47, 245, 215, 233, 204,  
102, 93, 209, 194, 88, 25, 141, 75, 46, 230, 122, 161, 151, 189, 70, 223, 138, 76, 110, 2, 27, 81, 85, 251, 83, 113, 162, 167, 116, 217,  
62, 216, 52, 224, 98, 139, 147, 198, 126, 229, 23, 208, 205, 66, 220, 49, 44, 56, 16, 130, 61, 7, 121, 159, 169, 24, 225, 48, 157, 252,  
196, 201, 244, 78, 153, 35, 79, 246, 57, 143, 206, 175, 59, 133, 250, 65, 179, 207, 3, 71, 97, 106, 135, 178, 149, 221, 174, 218, 213, 69,  
188, 73, 26, 33, 240, 226, 214, 64, 183, 247, 144, 168, 119, 30, 6, 255, 241, 155, 21, 53, 74, 80, 200, 160, 146, 242, 125, 31, 20, 190,  
90, 101, 156, 211, 108, 154, 118, 51, 248, 41, 171, 145, 199, 82, 99, 114, 115, 45, 237, 195, 132, 184, 100, 123, 186, 254, 120, 22, 67, 63,  
15, 36, 14, 136, 103, 77, 165, 239, 228, 243, 50, 142, 13, 34, 166, 235, 187, 17, 131, 238, 173, 231, 177, 60, 227, 18, 117, 140, 105, 0,  
109, 94, 172, 39, 249, 203, 107, 193, 10, 170, 128, 43, 137, 253, 42, 86  
};


unsigned int master_key[256] =
{
91, 30, 80, 10, 21, 90, 155, 219, 182, 213, 239, 92, 163, 56, 33, 23, 149, 185, 167, 158, 104, 221, 122, 84, 252, 156, 96, 251, 102, 178,
131, 40, 236, 229, 5, 41, 170, 233, 204, 0, 39, 93, 150, 71, 147, 137, 191, 1, 113, 120, 22, 87, 107, 24, 162, 66, 17, 48, 250, 222,
209, 169, 220, 133, 160, 193, 223, 254, 235, 198, 255, 205, 97, 37, 27, 98, 118, 129, 154, 101, 180, 103, 186, 242, 139, 53, 114, 105, 234, 208,
187, 196, 176, 140, 18, 153, 43, 31, 60, 3, 224, 249, 142, 226, 227, 124, 181, 25, 119, 134, 157, 166, 110, 2, 171, 203, 112, 174, 89, 32,
161, 20, 8, 14, 212, 100, 138, 127, 58, 211, 86, 106, 15, 125, 50, 54, 207, 192, 148, 237, 95, 9, 94, 199, 230, 45, 214, 175, 34, 165,
117, 231, 190, 63, 128, 168, 108, 36, 123, 248, 74, 29, 232, 19, 194, 240, 38, 72, 247, 253, 218, 159, 225, 244, 75, 188, 179, 151, 47, 6,
28, 62, 146, 85, 73, 49, 116, 183, 173, 246, 70, 189, 202, 61, 197, 99, 109, 164, 228, 68, 12, 67, 44, 78, 83, 121, 26, 201, 64, 11,
217, 200, 145, 69, 65, 111, 184, 77, 46, 243, 135, 136, 51, 130, 81, 238, 42, 126, 52, 55, 35, 177, 210, 16, 195, 172, 13, 216, 215, 115,
245, 76, 141, 4, 143, 144, 57, 206, 59, 132, 88, 152, 241, 7, 79, 82
};

unsigned int key4[256] =
{
91, 30, 80, 10, 21, 90, 155, 219, 182, 213, 239, 92, 163, 56, 33, 23, 149, 185, 167, 158, 104, 221, 122, 84, 252, 156, 96, 251, 102, 178,
131, 40, 236, 229, 5, 41, 170, 233, 204, 0, 39, 93, 150, 71, 147, 137, 191, 1, 113, 120, 22, 87, 107, 24, 162, 66, 17, 48, 250, 222,
209, 169, 220, 133, 160, 193, 223, 254, 235, 198, 255, 205, 97, 37, 27, 98, 118, 129, 154, 101, 180, 103, 186, 242, 139, 53, 114, 105, 234, 208,
187, 196, 176, 140, 18, 153, 43, 31, 60, 3, 224, 249, 142, 226, 227, 124, 181, 25, 119, 134, 157, 166, 110, 2, 171, 203, 112, 174, 89, 32,
161, 20, 8, 14, 212, 100, 138, 127, 58, 211, 86, 106, 15, 125, 50, 54, 207, 192, 148, 237, 95, 9, 94, 199, 230, 45, 214, 175, 34, 165,
117, 231, 190, 63, 128, 168, 108, 36, 123, 248, 74, 29, 232, 19, 194, 240, 38, 72, 247, 253, 218, 159, 225, 244, 75, 188, 179, 151, 47, 6,
28, 62, 146, 85, 73, 49, 116, 183, 173, 246, 70, 189, 202, 61, 197, 99, 109, 164, 228, 68, 12, 67, 44, 78, 83, 121, 26, 201, 64, 11,
217, 200, 145, 69, 65, 111, 184, 77, 46, 243, 135, 136, 51, 130, 81, 238, 42, 126, 52, 55, 35, 177, 210, 16, 195, 172, 13, 216, 215, 115,
245, 76, 141, 4, 143, 144, 57, 206, 59, 132, 88, 152, 241, 7, 79, 82
};


unsigned int key3[256] =
{
25, 236, 141, 158, 33, 118, 104, 10, 144, 45, 173, 155, 60, 44, 19, 223, 255, 92, 48, 31, 88, 152, 154, 166, 93, 34, 197, 162, 219, 135,
71, 98, 232, 204, 202, 24, 160, 1, 99, 168, 198, 122, 192, 9, 108, 217, 131, 59, 66, 77, 56, 67, 172, 218, 249, 147, 191, 129, 58, 115,
102, 7, 209, 133, 245, 61, 208, 195, 216, 17, 27, 163, 177, 114, 164, 0, 107, 78, 170, 205, 111, 234, 29, 75, 97, 157, 101, 85, 239, 68,
73, 100, 90, 37, 4, 254, 237, 149, 221, 22, 243, 241, 121, 206, 3, 13, 112, 109, 53, 64, 91, 190, 179, 14, 76, 32, 142, 12, 186, 247,
226, 228, 248, 169, 87, 89, 21, 215, 238, 188, 246, 203, 207, 5, 213, 178, 2, 16, 95, 233, 51, 151, 127, 110, 196, 55, 74, 36, 176, 23,
139, 69, 15, 39, 96, 38, 140, 137, 145, 79, 116, 252, 94, 194, 214, 52, 184, 165, 126, 174, 167, 156, 242, 83, 119, 8, 128, 253, 125, 80,
220, 181, 138, 250, 81, 148, 199, 18, 161, 150, 136, 182, 130, 11, 26, 134, 113, 235, 63, 123, 171, 229, 187, 65, 106, 132, 50, 175, 143, 210,
20, 120, 185, 46, 82, 62, 42, 43, 30, 211, 84, 124, 117, 47, 201, 41, 159, 212, 70, 35, 57, 244, 231, 227, 193, 240, 153, 103, 222, 180,
189, 146, 86, 251, 183, 28, 230, 54, 224, 49, 225, 6, 40, 72, 200, 105
};



unsigned int Substitution_Inverse_Table[BLOCKSIZE] = {
239, 5, 79, 138, 28, 35, 164, 111, 22, 41, 248, 29, 10, 222, 212, 210, 108, 227, 235, 44, 178, 168, 207, 100, 115, 65, 152, 80, 48, 19,
163, 177, 24, 153, 223, 125, 211, 37, 1, 243, 8, 189, 254, 251, 106, 197, 68, 55, 117, 105, 220, 187, 92, 169, 54, 52, 107, 128, 49, 132,
233, 110, 90, 209, 157, 135, 103, 208, 6, 149, 74, 139, 9, 151, 170, 67, 77, 215, 123, 126, 171, 81, 193, 84, 43, 82, 255, 51, 64, 0,
180, 42, 17, 61, 241, 47, 3, 140, 94, 194, 202, 181, 60, 214, 15, 238, 141, 246, 184, 240, 78, 7, 16, 85, 195, 196, 88, 236, 186, 162,
206, 112, 70, 203, 31, 176, 98, 46, 250, 26, 109, 228, 200, 133, 23, 142, 213, 252, 76, 95, 237, 66, 221, 129, 160, 191, 174, 96, 27, 144,
50, 72, 20, 124, 185, 167, 182, 118, 30, 113, 173, 71, 86, 36, 18, 216, 224, 87, 161, 114, 249, 190, 242, 230, 146, 131, 33, 232, 143, 136,
4, 14, 11, 158, 201, 32, 204, 226, 150, 73, 179, 34, 53, 247, 63, 199, 120, 13, 97, 192, 172, 121, 38, 245, 59, 102, 130, 137, 101, 62,
40, 183, 12, 148, 156, 57, 91, 89, 147, 21, 104, 145, 25, 75, 93, 116, 155, 234, 218, 99, 69, 231, 2, 58, 45, 225, 39, 198, 229, 217,
154, 166, 175, 219, 122, 56, 127, 159, 188, 244, 134, 83, 119, 253, 205, 165
};



int main(int argc, char *argv[]) 
{
	
	
	unsigned int i = 0;
	
	int testing_Key_Dependency = 1;
	
	Init_RNG();
	Encrytion_MasterKey();
	
	printf( "\n");
	printf( "------------------------------ Master Key --------------------------------\n");
	printf( "\n");

	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		if((i % 16) == 0)printf( "\n");
		printf( " %3d ", master_key[i]);
		
	}
	
	printf( "\n");
	printf( "------------------------------------------------------------------------------\n");
	printf( "\n");
	
	Key_16bits();
	
	printf( "\n");
	printf( "------------------------------ 16 bits Master Key --------------------------------\n");
	printf( "\n");

	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		if((i % 16) == 0)printf( "\n");
		printf( " %3d ", mkey_16bit[i]);
		
	}
	printf( "\n");
	printf( "------------------------------------------------------------------------------\n");
	printf( "\n");
	
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		sv[i] = start_val;	
		enc[i] = start_val;
	}
	
	
	
	printf( "\n");
	printf( "------------------------------ Data to encrypt --------------------------------\n");
	printf( "\n");

	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		if((i % 16) == 0)printf( "\n");
		printf( " %3d ", sv[i]);
		
	}
	
	printf( "\n");
	printf( "------------------------------------------------------------------------------\n");
	printf( "\n");
	
	Data_Complement();
	
	printf( "\n");
	printf( "------------------------------ Complemeted Plain Text --------------------------------\n");
	printf( "\n");

	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		if((i % 16) == 0)printf( "\n");
		printf( " %3d ", enc[i]);
		
	}
	
	printf( "\n");
	printf( "------------------------------------------------------------------------------\n");
	printf( "\n");

	Sub_key_gen();	
	
	for(i = 0; i < Rounds; i++)
	{
		printf("Round: %d", i);
		
		printf( "\n");
		printf( "------------------------------ 16 bits Sub Key --------------------------------\n");
		printf( "\n");
		for(j = 0; j < BLOCKSIZE; j++)
		{

			if((j % 16) == 0)printf( "\n");
			printf( " %3d ", key[i][j]);
							

		}
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");
	}
	
	Masking_kEY();
	
//First Encryption
	for(i = 0; i < Rounds; i++)
	{
		Diffusion_XOR(0);
		NoOperation_Reduced();
		Ceasar_Shift_Var(0);
		Diffusion_XOR(0);
		Ceasar_Shift(key[i][123], 0);//Rotate
		Diffusion_XOR(0);
		NoOperation_Reduced();
		XOR_Key(0);
		Diffusion_XOR(0);
		NoOperation_Reduced();
		if(i < Rounds - 1)Shuffle(0);
		else Shuffle(1);
	}
	
	if(testing_Key_Dependency)
	{ 
	
		for (i = 0; i < BLOCKSIZE; i++)
		{
			enc_Save[i] = enc[i];
			sv[i] = start_val;	
			enc[i] = start_val;
		
		}
		
		//--------------------------------------------
		//key[0] = (key[0] + 1) % 256; //Changing Key
		//--------------------------------------------
		
		//--------------------------------------------
		enc[128] = (enc[128] + 1) % MAX_VAL; //Changing Plaintext
		//--------------------------------------------

//Second Encryption	
		for(i = 0; i < Rounds; i++)
		{
			Diffusion_XOR(0);
			NoOperation_Reduced();
			Ceasar_Shift_Var(0);
			Diffusion_XOR(0);
			Ceasar_Shift(key[i][123], 0);//Rotate
			Diffusion_XOR(0);
			NoOperation_Reduced();
			XOR_Key(0);
			Diffusion_XOR(0);
			NoOperation_Reduced();
			if(i < Rounds - 1)Shuffle(0);
			else Shuffle(1);
		}
    			

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if(enc[i] == enc_Save[i]) Count_Equal++;
		}
		
		for (i = 0; i < BLOCKSIZE; i++)
		{
			
			BitsBuffer = (enc[i] ^ enc_Save[i]);
			BitsBuffer = 65535 - BitsBuffer;

			
			for(j = 0; j < DATA_BITS; j++)
			{
				Count_Equal_Bits += BitsBuffer & 0x01;
				BitsBuffer = BitsBuffer >> 1;
			}
			 
		}
		
		Equal_Bits_Percent = (double)Count_Equal_Bits / (256 * DATA_BITS);
	
		printf( "\n\n\n");
		printf( "Count Equal Bytes  =  %3d ", Count_Equal);
		printf( "\n\n");
		printf( "Count Equal Bits  =  %3d ", Count_Equal_Bits);
		printf( "\n");
		printf( "Equal Bits in Percent =  %7f ", Equal_Bits_Percent);
		printf( "\n\n\n");
		
		//Only Key!!
		//--------------------------------------------
		//key[0][0] = (key[0][0] - 1) % MAX_VAL; //Changing Key
		//--------------------------------------------
		

		
	}
	
	if(testing_Key_Dependency)
	{
		for (i = 0; i < BLOCKSIZE; i++)
		{
			dec[i] = enc_Save[i];
		}
	}
	else
	{
		for (i = 0; i < BLOCKSIZE; i++)
		{	
			dec[i] = enc[i];
		}

	}

		
	
	

	UnMasking_KEY();
	Sub_key_gen();
		
	dec[10] = (dec[10] + 1) % MAX_VAL;
	
	for(i = 0; i < Rounds; i++)
	{
		Re_Shuffle(0);
		NoOperation_Reduced();
		Re_Diffusion_XOR(0);
		Re_XOR_Key(0);
		NoOperation_Reduced();
		Re_Diffusion_XOR(0);
		Ceasar_Re_Shift(key[(Rounds - 1) - i][123], 0);//Re_Rotate
		Re_Diffusion_XOR(0);
		Ceasar_Re_Shift_Var(0);
		NoOperation_Reduced();
		if(i < Rounds - 1)Re_Diffusion_XOR(0);
		else Re_Diffusion_XOR(1);
	}
	
	
	printf( "\n\n\n");
	
	
	
	return 0;
}



void Test_Distribution_of_Bytes(unsigned int X[], unsigned int Size)
{
			unsigned int i = 0;
            unsigned int Count_Distribution[256];
            double Expected_Value = 0.0;
            double Chi_Square_N = 0.0;
            
            for (i = 0; i < Size; i++)
            {
                Count_Distribution[i] = 0;
            }

            
            for (i = 0; i < Size; i++)
            {
                Count_Distribution[X[i]]++;
            }

            Expected_Value = (double)(Size) / 256;

            

            for (i = 0; i < 256; i++)
            {
                Chi_Square_N += (( ((double)(Count_Distribution[i])) - Expected_Value) * ( ((double)(Count_Distribution[i])) - Expected_Value)) / Expected_Value;
            }

            //Chi Square (Variance)
            Chi_Square_N = Chi_Square_N / 256;


            //Mean Value
            double MW = 0;
            double Sum = 0;
            for (i = 1; i < 256; i++)
            {
                MW = MW + ((double)(Count_Distribution[i])) * i;
                Sum = Sum + (double)(Count_Distribution[i]);
            }

            MW = MW / Sum;

            

            printf("\nChi Square (Variance) = %#g\n", Chi_Square_N);
            printf("Mean Value = %#g\n", MW);
            printf("Expected Count = %#g\n", Expected_Value);
        
            

}

void Diffusion_XOR(int Display)
{
	
	
	for (i = 0; i < BLOCKSIZE - 1; i++)
	{
		enc[i + 1] = enc[i] ^ enc[i + 1];
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Re_Diffusion_XOR(int Display)
{
	
	
	for (i = BLOCKSIZE-2; i >= 0; i--)
	{
		dec[i + 1] = dec[i] ^ dec[i + 1];
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Complemented Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

		Data_Re_Complement();

		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");
	}

	
}


void Ceasar_Shift(unsigned int k, int Display)//Rotate
{
	
	
	int ki = k % MAX_VAL;
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = (enc[i] + ki) % MAX_VAL;
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Ceasar_Re_Shift(unsigned int k, int Display)//Re_Rotate
{
	
	
	int ki = k % MAX_VAL;
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = (dec[i] - ki) % MAX_VAL;
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}





void Ceasar_Shift_Var(int Display)
{
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = (enc[i] + key[Rounds][i]) % MAX_VAL;
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
	}

	
}



void Ceasar_Re_Shift_Var(int Display)
{
	
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = (dec[i] - key[Rounds][i]) % MAX_VAL;
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
	}

	
}







void Complement(int Display)
{
	
	
	unsigned int BS = BLOCKSIZE - 1;
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{	
		enc[i] = 255 - enc[i];
	}
	
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Re_Complement(int Display)
{
	
	
	unsigned int BS = BLOCKSIZE - 1;
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = 255 - dec[i];
	}

	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}


void Reflect(int Display)
{
	
	
	unsigned int BS = BLOCKSIZE - 1;
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{	
		dec[i] = enc[BS - i];
	}
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = dec[i];
	}

	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Re_Reflect(int Display)
{
	
	
	unsigned int BS = BLOCKSIZE - 1;
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = dec[BS - i];
	}

	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = enc[i];
	}

	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Substitution(int Display)
{
	
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = Substitution_Table[enc[i]];
	}
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = dec[i];
	}

	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Re_Substitution(int Display)
{
	
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = Substitution_Inverse_Table[dec[i]];;
	}
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = enc[i];
	}

	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
	}

	
}




void Shuffle(int Display)
{
	
	
	unsigned int i_2 = BLOCKSIZE;
	unsigned int Pointer = i_2/2;
	
	
	for (i = 0; i < BLOCKSIZE; i = i + 2)
	{
		i_2 = i / 2;
		dec[i] = enc[i_2 + Pointer];
		dec[i+ 1] = enc[i_2];
	}
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = dec[i];
	}

	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Re_Shuffle(int Display)
{
	
	
	
	unsigned int i_2 = BLOCKSIZE;
	unsigned int Pointer = i_2/2;
	
	
	for (i = 0; i < BLOCKSIZE; i = i + 2)
	{
		i_2 = i / 2;
		enc[i_2] = dec[i + 1];
		enc[i_2 + Pointer] = dec[i];
	}

	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = enc[i];
	}

	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void XOR_Key(int Display)
{
	
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		enc[i] = enc[i] ^ key[Rounds][i];
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Encrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", enc[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}



void Re_XOR_Key(int Display)
{
	
	
	
	for (i = 0; i < BLOCKSIZE; i++)
	{
		dec[i] = dec[i] ^ key[Rounds][i];
	}
	
	
	if(Display)
	{	
		printf( "\n");
		printf( "------------------------------ Decrypted Data --------------------------------\n");
		printf( "\n");
	

		for (i = 0; i < BLOCKSIZE; i++)
		{
			if((i % 16) == 0)printf( "\n");
			printf( " %3d ", dec[i]);
		
		}
		
		printf( "\n");
		printf( "------------------------------------------------------------------------------\n");
		printf( "\n");

	}

	
}

void Data_Complement()
{
	int k;
	
	unsigned int temp;
	
	for (k = 0; k < BLOCKSIZE; k++)
	{	
		temp = enc[k];
		enc[k] = temp << 8;
		enc[k] = enc[k] | (255 - temp);
	}
}



void Data_Re_Complement()
{
	int k;
	
	unsigned int temp;
	
	for (k = 0; k < BLOCKSIZE; k++)
	{	
		temp = dec[k];
		dec[k] = temp >> 8;
	}
}

void Key_16bits()
{
	int k;
	
	unsigned int temp;
	
	for (k = 0; k < BLOCKSIZE; k++)
	{	
		temp = master_key[k];
		mkey_16bit[k] = (temp << 8) | k;
	}
}


void Encrytion_MasterKey()
{
	unsigned int BlockSize = BLOCKSIZE;
	unsigned int buffer[BlockSize];
	unsigned int ki = 0;
	unsigned int Last_Value = 1;
	unsigned int BS = BlockSize - 1;
	unsigned int i_2 = BlockSize;
	unsigned int Pointer = i_2/2;

	unsigned int j = 0;
	unsigned int k = 0;

	int RN = (rand() % 256) + 2;
	
	for (k = 0; k < RN; k++)
	{

		for (j = 0; j < 3; j++)
		{

			//Ceasar_Shift_Var
			for (i = 0; i < BlockSize; i++)
			{
				RandomNumbers[i] = (RandomNumbers[i] + master_key[i]) % 256;
				//printf("Random numbers Ceaser Shift are:%u",RandomNumbers[i]);
			}

			//Substitution
			for (i = 0; i < BlockSize; i++)
			{
				buffer[i] = Substitution_Table[RandomNumbers[i]];
				//printf("Random numbers of BUFFER are:%u",buffer[i]);
			}


			//Ceasar Shift
			for (i = 0; i < BlockSize; i++)
			{
				RandomNumbers[i] = (buffer[i] + RandomRNG_1) % 256;
				//printf("Random numbersCeasershift again are: %u",RandomNumbers[i]);
			}

			//Complement
			for (i = 0; i < BlockSize; i++)
			{
				RandomNumbers[i] = 255 - RandomNumbers[i];
				//printf("Random numbers complement are:%u",RandomNumbers[i]);
			}

			//Diffusion
			Last_Value = 1;
			for (i = 0; i < BlockSize; i++)
			{
				ki = Last_Value;
				Last_Value = RandomNumbers[i];

				RandomNumbers[i] = (RandomNumbers[i] + ki) % 256;
				//printf("Random numbers of Difuusion are:%u",RandomNumbers[i]);

			}

			//Substitution
			for (i = 0; i < BlockSize; i++)
			{
				buffer[i] = Substitution_Table[RandomNumbers[i]];
				//printf("Random numbers of Substitution are:%u",buffer[i]);
			}


			//Reflect
			for (i = 0; i < BlockSize; i++)
			{
				RandomNumbers[i] = buffer[BS - i];
				//printf("Random numbers Reflect are:%u",RandomNumbers[i]);
			}


			//Shuffle
			for (i = 0; i < BlockSize; i = i + 2)
			{
				i_2 = i / 2;
				buffer[i] = RandomNumbers[i_2 + Pointer];
				buffer[i + 1] = RandomNumbers[i_2];
				//printf("Random numbers shuffle are:%u",buffer[i]);
			}

			//Ceasar Shift
			for (i = 0; i < BlockSize; i++)
			{
				buffer[i] = (buffer[i] + RandomRNG_2) % 256;
				//printf("Random numbers ceaser shift are:%u",buffer[i]);
			}


			//Diffusion
			Last_Value = 1;
			for (i = 0; i < BlockSize; i++)
			{
				ki = Last_Value;
				Last_Value = RandomNumbers[i];

				RandomNumbers[i] = (buffer[i] + ki) % 256;
				//printf("Random numbers of DIffusion are:%u",RandomNumbers[i]);

			}

			//Ceasar_Shift_Var
			for (i = 0; i < BlockSize; i++)
			{
				RandomNumbers[i] = (RandomNumbers[i] + key4[i]) % 256;
			}

			//Changing Random Key for RNG
			for (i = 0; i < BlockSize; i++)
			{
				master_key[i] = buffer[i];
				//printf("Random numbers using RNG are:%u",master_key[i]);
			}
			
			RandomRNG_1 = master_key[key4[11]];
			RandomRNG_1 = master_key[key4[31]];
			//printf("Random numbers are:%u",RandomRNG_1);

		}//j
	}
}




void Masking_kEY()
{
    printf( "\n");
	printf( "------------------------------ Masked 16 bit Master Key --------------------------------\n");
	printf( "\n");
	for(i=0;i<BLOCKSIZE; i++)
	{
    	msk_master_key[i]=mkey_16bit[i]^key4[i];
    	//msk_master_key[i]=key3[i];
    	
    	if((i % 14 == 0))printf( "\n");
    	printf("%3d\t",msk_master_key[i]);
	}
	printf( "\n");
	printf( "------------------------------------------------------------------------------\n");
	printf( "\n");
}



void UnMasking_KEY()
{
    printf( "\n");
	printf( "------------------------------ Unmasked 16 bit Master Key --------------------------------\n");
	printf( "\n");
	for(i=0;i<BLOCKSIZE; i++)
	{
    	//unmsk_master_key[i]=msk_master_key[i]^key4[i];
    	
    	if((i % 14 == 0))printf( "\n");
    	printf("%3d\t",mkey_16bit[i]);
	}
	printf( "\n");
	printf( "------------------------------------------------------------------------------\n");
	printf( "\n");
}


void Init_RNG()
{
	srand(time( NULL ) );

	for (i = 0; i < BLOCKSIZE; i++)
	{
		RandomNumbers[i] = rand() % 256;
	}

	RandomRNG_1 = rand() % 256;
	RandomRNG_2 = rand() % 256;

	//Test_Distribution_of_Bytes(	RandomNumbers, 256);

}

void Sub_key_gen()
{
	int x, y;
	
	
	for(x = 0; x < Rounds; x++)
	{
		key[x][0] = (mkey_16bit[y] ^ (key_raw[y] ^ (key4[x] * 159357)% 65536)%65536) % 65536;
		for(y = 1; y < BLOCKSIZE; y++)
		{
			key[x][y] = (mkey_16bit[y] ^ (key_raw[y] ^ key4[(x * y + 159)%65536])%65536) % 65536; 
		}
	}
	
}



void NoOperation_Reduced()
{
		//Side-Channel-Fighting
		//return;
		static byte cs = 3;
		
		if(cs < 2)
		{
			cs++;
			x_Nop = (x_Nop >> 2) & 4;
		}	
		else
		{
			x_Nop = Get_RandomByte() & 4;
			cs = 0;
		}
	
		asm("NOP");
		for (i_Nop = 0; i_Nop < x_Nop; i_Nop++)
		{
			asm("NOP");
		}
		
		asm("NOP");

}



byte Get_RandomByte()
{
/*	static int PP = 255;
	PP++;
	
	if(PP > 255)
	{
		PP = 0;
		
		return (byte)RandomNumbers[PP];
	}
	else
	{
		return (byte)RandomNumbers[PP];
	}*/
	
	return (byte)(rand() % 256);
}
