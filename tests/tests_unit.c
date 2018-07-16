#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "bip32.h"
#include "utils.h"
#include "ecc.h"
#include "config.h"

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <stdint.h>


int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode);

int wallet_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;

    char *kp = strdup(keypath);
    if (!kp) {
        return 1;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, 32);
    memcpy(node->private_key, privkeymaster, 32);
    hdnode_fill_public_key(node);

    char *pch = strtok(kp + 2, delim);
    if (pch == NULL) {
        goto err;
    }
    int has_prm = 0;
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        size_t pch_len = strlens(pch);
        for ( ; i < pch_len; i++) {
            if (strchr(prime, pch[i])) {
                if (i != pch_len - 1) {
                    goto err;
                }
                prm = 1;
                has_prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }
        if (prm && pch_len == 1) {
            goto err;
        }
        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (hdnode_private_ckd_prime(node, idx) != 0) {
                goto err;
            }
        } else {
            if (hdnode_private_ckd(node, idx) != 0) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    if (!has_prm) {
        goto err;
    }
    free(kp);
    return 0;

err:
    free(kp);
    return 1;
}

char str[128][112];
uint8_t sig[64];
int res;

const char *key[]={"7fd1f7ea8609958436e496f8904002db76a3129905f8f38ba1d52b4b8f0310d00398e884db40a62a70104f7df792f4d2e0d96ff6939cc34fb7a9846ef9e9268e3791a3021524b79f5ce26e86183e19b21a233855d648ac6f35516289ddc6e6fee69bf59f84c35a8571f4fdaa29c95908f789e3b1cf41051377f1b8698e30fa61",
			 "7fd1f7ea8609958436e496f8904002db76a3129905f8f38ba1d52b4b8f0310d00398e884db40a62a70104f7df792f4d2e0d96ff6939cc34fb7a9846ef9e9268e3791a3021524b79f5ce26e86183e19b21a233855d648ac6f35516289ddc6e6fee69bf59f84c35a8571f4fdaa29c95908f789e3b1cf41051377f1b8698e30fa62",
			 "7fd1f7ea8609958436e496f8904002db76a3129905f8f38ba1d52b4b8f0310d00398e884db40a62a70104f7df792f4d2e0d96ff6939cc34fb7a9846ef9e9268e3791a3021524b79f5ce26e86183e19b21a233855d648ac6f35516289ddc6e6fee69bf59f84c35a8571f4fdaa29c95908f789e3b1cf41051377f1b8698e30fa63",
			 "7fd1f7ea8609958436e496f8904002db76a3129905f8f38ba1d52b4b8f0310d00398e884db40a62a70104f7df792f4d2e0d96ff6939cc34fb7a9846ef9e9268e3791a3021524b79f5ce26e86183e19b21a233855d648ac6f35516289ddc6e6fee69bf59f84c35a8571f4fdaa29c95908f789e3b1cf41051377f1b8698e30fa64",
			 "7fd1f7ea8609958436e496f8904002db76a3129905f8f38ba1d52b4b8f0310d00398e884db40a62a70104f7df792f4d2e0d96ff6939cc34fb7a9846ef9e9268e3791a3021524b79f5ce26e86183e19b21a233855d648ac6f35516289ddc6e6fee69bf59f84c35a8571f4fdaa29c95908f789e3b1cf41051377f1b8698e30fa65",
	 	  };


static void getpub(char *path)
{
    int i;
    char temp[112];
    for(i=0;i<(int)(sizeof(key)/sizeof(*key));i++)
   {
    HDNode node;
    uint8_t private_key_master[32],chain_code_master[32];
    hdnode_from_seed(utils_hex_to_uint8(key[i]),strlen(key[i]), &node);
    memcpy(private_key_master,node.private_key,32);
    memcpy(chain_code_master,node.chain_code,32);
    wallet_generate_key(&node, path, private_key_master, chain_code_master);
    
    memset(temp, 0, sizeof(temp));
    hdnode_serialize_public(&node, temp, sizeof(temp));
    memcpy(str[i],temp,strlen(temp));
   }
}

static void sign(char *path,char *msg, char *pub)
{
    int i;
    for(i=0;i<(int)(sizeof(key)/sizeof(*key));i++)
  {
    HDNode node;   
    uint8_t private_key_master[32],chain_code_master[32];
    hdnode_from_seed(utils_hex_to_uint8(key[i]),strlen(key[i]), &node);
    memcpy(private_key_master,node.private_key,32);
    memcpy(chain_code_master,node.chain_code,32);
    wallet_generate_key(&node, path, private_key_master, chain_code_master);
    uint8_t data[32];
    memcpy(data, utils_hex_to_uint8(msg), 32);

    if(strcmp(pub,str[i])==0)
    {   
	res=bitcoin_ecc.ecc_sign_digest(node.private_key, data, sig, NULL, ECC_SECP256k1); 
    }
  }
}

static void send_cmd(int conn,char *cmd)
{
 int c=0;
 char seps[]= ":|",action1[]="getpub",action2[]="sign";
 char *token;
 char *arg1,*arg2,*arg3,*arg4;

 token = strtok( cmd, seps );

 while(token !=NULL)
 {  c++;
    if(c==1)arg1=token;
    if(c==2)arg2=token;
    if(c==3)arg3=token;
    if(c==4)arg4=token;
    token=strtok(NULL,seps);
 }
if(c!=2&&c!=4)
 {
	 char e[]="getpub or sign with path!\n";
	 write(conn,e,sizeof(e));
 }

if(c==2&&strcmp(arg1,action1)==0)
   {	getpub(arg2);
	int m=(int)(sizeof(key)/sizeof(*key));
	write(conn, str[m], sizeof(str[m]));
   }
if(c==4&&strcmp(arg1,action2)==0)
{
	sign(arg2,arg3,arg4);

	ECDSA_SIG *signature = ECDSA_SIG_new();
	BN_bin2bn(sig, 32, signature->r);
	BN_bin2bn(sig + 32, 32, signature->s);
	char *r,*s,temp[256],sss[]="|";
	r=BN_bn2dec(signature->r);
	s=BN_bn2dec(signature->s);
	strcpy(temp,r);
	strcat(temp,sss);
	strcat(temp,s);

	write(conn, temp,strlen(r)+strlen(s)+sizeof(sss));
   }

}
int main(void)
{
	struct sockaddr_in servaddr , cliaddr;

	int listenfd , connfd;
	pid_t childpid;
	socklen_t clilen;

	if((listenfd = socket(AF_INET , SOCK_STREAM , 0)) < 0)
	{
		perror("socket error");
		exit(1);
	}

	bzero(&servaddr , sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	if(bind(listenfd , (struct sockaddr*)&servaddr , sizeof(servaddr)) < 0)
	{
		perror("bind error");
		exit(1);
	}

	if(listen(listenfd , LISTENQ) < 0)
	{
		perror("listen error");
		exit(1);
	}

	for( ; ; )
	{
		clilen = sizeof(cliaddr);
		if((connfd = accept(listenfd , (struct sockaddr *)&cliaddr , &clilen)) < 0 )
		{
			perror("accept error");
			exit(1);
		}

		if((childpid = fork()) == 0) 
		{
			close(listenfd);
			ssize_t n;
			char buff[MAX_LINE];
			while((n = read(connfd , buff , MAX_LINE)) > 0)
			{
				send_cmd(connfd , buff);
			}
			exit(0);
		}
		close(connfd);
	}
	close(listenfd);
  return 0;
}
