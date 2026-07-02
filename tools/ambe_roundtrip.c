/* ambe_roundtrip.c — for a VALID on-air 72-bit AMBE frame, 72->49->72 must be
 * identity. Any real voice frame that is NOT identity means the shared 49<->72
 * conversion (used by BOTH ipsc2hbp and cc2obp, never by hblink3) is lossy. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../../ipsc2hbpc/src/dmr/dmr.h"
static int hb(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: ambe_roundtrip <72bit-ambe-hex(9 bytes)>...\n"); return 2; }
    int bad=0;
    for(int a=1;a<argc;a++){
        uint8_t in[9]; int n=0; const char*s=argv[a];
        for(;s[0]&&s[1]&&hb(s[0])>=0&&n<9;s+=2) in[n++]=(uint8_t)((hb(s[0])<<4)|hb(s[1]));
        if(n!=9){ printf("skip %s (need 9 bytes)\n",argv[a]); continue; }
        dmr_bit b72[72]; dmr_bytes_to_bits(in,9,b72);
        dmr_bit d49[49]; dmr_ambe_72_to_49(b72,d49);
        dmr_bit r72[72]; dmr_ambe_49_to_72(d49,r72);
        uint8_t out[9]; dmr_bits_to_bytes(r72,72,out);
        int id=memcmp(in,out,9)==0;
        printf("%s -> 49 -> %.*s : %s\n", argv[a], 18, "", id?"IDENTITY":"CHANGED (lossy!)");
        printf("    in : "); for(int i=0;i<9;i++)printf("%02x",in[i]);
        printf("\n    out: "); for(int i=0;i<9;i++)printf("%02x",out[i]); printf("\n");
        if(!id)bad++;
    }
    return bad?1:0;
}
