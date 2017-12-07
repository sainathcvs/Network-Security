#define MAXLINES 4096

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

struct ctr_state
{
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned int number;
    unsigned char ecount[AES_BLOCK_SIZE];
};

void init_counter(struct ctr_state *s, const unsigned char iv[16]){
	s->number = 0;
	memset(s->ecount,0,AES_BLOCK_SIZE);
	memset(s->iv+8,0,8);
	memcpy(s->iv,iv,8);
}

struct ctr_state s;

void act_as_server(unsigned char* encrypted_key,int port,char* dest_ip,int d_port)
//int main()
{
	struct sockaddr_in server,client,sshserv; /* IPv4 socket address structure */
 	socklen_t len_client;
	int server_fd,client_fd,msg_len,n,pid,sshd;
	struct hostent *d_ip;
	char s_text[MAXLINES],r_text[MAXLINES],encr_text[MAXLINES];
	AES_KEY aes_key;
	// unsigned char* encrypted_key;
	// encrypted_key = "1234567887654321";
	char e_text[MAXLINES];

	unsigned char iv[AES_BLOCK_SIZE];
	
	server_fd = socket(AF_INET, SOCK_STREAM,0);
	if(server_fd<0){
		perror("Problem in creating socket");
		exit(1);
	}
	
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr= htonl(INADDR_ANY);
	server.sin_port =  htons(port);

	//d_ip = gethostbyname("localhost");
	d_ip = gethostbyname(dest_ip);
	//printf("%s\n", d_ip);
	//d_port = atoi("22");
	sshserv.sin_family = AF_INET;
	sshserv.sin_addr.s_addr = ((struct in_addr*)(d_ip->h_addr))->s_addr;
	//printf("%d\n", sshserv.sin_addr.s_addr);
	sshserv.sin_port =  htons(d_port);

	if(bind(server_fd, (struct sockaddr*) &server, sizeof(server))<0)
	{
		fprintf(stderr, "%s\n", "ERROR: Couldnt bind on socket.");
		exit(EXIT_FAILURE);
	}
	listen(server_fd,10);
	//fprintf(stderr,"%s\n","Waiting for connections...");

	len_client = sizeof(client);
	while(1)
	{
		client_fd = accept(server_fd, (struct sockaddr *) &client, &len_client);
		//fprintf(stderr, "%s\n", "Connection started");
		pid = fork();
		
		fcntl(1, F_SETFL, O_NONBLOCK);
		if(pid==0){
			//fprintf(stderr, "%s\n", "new process.");
			sshd = socket(AF_INET,SOCK_STREAM,0);
			if(sshd<0){
				fprintf(stderr, "%s\n", "Error in connecting ssh socket");
				exit(1);
			}
			if(connect(sshd,(struct sockaddr *) &sshserv, sizeof(sshserv))<0){
				fprintf(stderr, "%s\n", "Error in connecting socket");
				exit(1);
			}
			
			fcntl(sshd, F_SETFL, O_NONBLOCK);
			fcntl(client_fd, F_SETFL, O_NONBLOCK);
			fcntl(0, F_SETFL, O_NONBLOCK);
			while(1){
				//fprintf(stderr, "%s\n", "in while1");

				if(AES_set_encrypt_key(encrypted_key,128,&aes_key)<0){
					fprintf(stderr, "%s\n", "could not set encryption key");
				}

				while((msg_len=read(sshd,e_text,MAXLINES))>0){
					//fprintf(stderr, "read from server:%s\n", s_text);
					init_counter(&s,iv);
					AES_ctr128_encrypt(e_text, s_text, msg_len, &aes_key, s.iv, s.ecount, &s.number);
					//fprintf(stderr, "reads decrytpted ...%s... from server.\n", s_text);										
					msg_len=write(client_fd,s_text,msg_len);
					usleep(16000);
					//fprintf(stderr, "wrote to client:%s\n", s_text);
					if(msg_len<MAXLINES){
						//fprintf(stderr, "%s\n", "breaking from server read");
						break;
					}
				}
				while((msg_len=read(client_fd,r_text,MAXLINES))>0){
					//fprintf(stderr, "read from client:%s n:%d\n", r_text,msg_len);
					init_counter(&s,iv);
					AES_ctr128_encrypt(r_text, e_text, msg_len, &aes_key, s.iv, s.ecount, &s.number);
					//fprintf(stderr, "writes encrytpted ...%s... to server.\n", e_text);
					msg_len=write(sshd,e_text,msg_len);
					//fprintf(stderr, "wrote to server:%s n:%d\n", r_text,msg_len);
					if(msg_len<MAXLINES){
						//fprintf(stderr, "breaking from client read\n");
						break;
					}
				}
			}
			//fprintf(stderr, "%s\n", "exiting child process");
			close(client_fd);
			close(sshd);
			exit(0);
		}else{
			if(pid<0){
				//fprintf(stderr, "%s\n", "Error in fork");
				exit(1);
			}
			//fprintf(stderr, "Closing client fd. for pid %d\n",pid);
			close(client_fd);
		}
	}
}


void act_as_client(unsigned char* encrypted_key,char* dest_ip,int port)
//int main()
{
	struct sockaddr_in client; /* IPv4 socket address structure */
	int client_fd,connect_start,msg_len;
	char s_text[MAXLINES],r_text[MAXLINES],encr_text[MAXLINES];
	AES_KEY aes_key;
	struct hostent *d_ip;
	// unsigned char* encrypted_key;
	// encrypted_key = "1234567887654321";
	char e_text[MAXLINES];

	unsigned char iv[AES_BLOCK_SIZE];
	
	client_fd = socket(AF_INET, SOCK_STREAM,0);
	if(client_fd<0){
		perror("Problem in creating socket");
		exit(1);
	}
	//port = atoi("3125");
	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	d_ip = gethostbyname(dest_ip);
	client.sin_addr.s_addr = ((struct in_addr*)(d_ip->h_addr))->s_addr;
	//client.sin_addr.s_addr= inet_addr(LOCALHOST);
	client.sin_port =  htons(port);

	connect_start = connect(client_fd, (struct sockaddr*) &client, sizeof(client));
	if(connect_start<0){
		perror("Problem in establishing the connection");
		exit(1);	
	}
	// if(write(client_fd,iv,AES_BLOCK_SIZE)<0){
	// 	fprintf(stderr, "%s\n", "IV not sent");
	// }
	fcntl(0, F_SETFL, O_NONBLOCK);
	fcntl(client_fd, F_SETFL, O_NONBLOCK);
	fcntl(1, F_SETFL, O_NONBLOCK);

	while(1)
	{
		//fprintf(stderr, "%s\n", "reading from stdin.");
		if(AES_set_encrypt_key(encrypted_key,128,&aes_key)<0){
			fprintf(stderr, "%s\n", "could not set encryption key");
		}
		while((msg_len=read(0,s_text,MAXLINES))>0){			
			//fprintf(stderr, "%s\n", "About to write to server");
			init_counter(&s,iv);
			AES_ctr128_encrypt(s_text, e_text, msg_len, &aes_key, s.iv, s.ecount, &s.number);
			//fprintf(stderr, "Client writes encrytpted ...%s... to server.\n", e_text);
			//write(client_fd,s_text,n);
			write(client_fd,e_text,msg_len);
			//fprintf(stderr, "Client writes %s to server.\n", s_text);
			if(msg_len<MAXLINES){
				//fprintf(stderr, "%s\n", "breaking from server write");
				break;
			}
		}
		//fprintf(stderr, "%s\n", "reading from server");
		while((msg_len=read(client_fd,e_text,MAXLINES))>0){
			//fprintf(stderr, "Client read %s from server.\n", r_text);
			init_counter(&s,iv);
			AES_ctr128_encrypt(e_text, r_text, msg_len, &aes_key, s.iv, s.ecount, &s.number);
			//fprintf(stderr, "Client writes decrytpted ...%s... to stdout.\n", e_text);
			write(1,r_text,msg_len);
			if(msg_len<MAXLINES){
				//fprintf(stderr, "%s\n", "breaking from server read.");
				break;
			}
		}
	}

}


int main(int argc, char **argv)
{
	bool is_acting_as_server = false,is_key_given = false;
	char pub_key[200],filename[30];
	char option;
	char* dest_port;
	char* dest_ip;
	char* key;
	int listen_port,ctr;
	unsigned char encrypted_key[1000];
	//encrypted_key = "1234567887654321";
	FILE *fd;

	while ((option = getopt(argc, argv, "l:k:")) != -1) {
		switch(option) {
			case 'l':
				listen_port = atoi(optarg);
				is_acting_as_server = true;
				break;
			case 'k':
				strcpy(filename,optarg);
				is_key_given = true;
				break;
			default:
				printf("error: unrecognized command-line options \n");
				return 0;
		}
	}

	if(!is_key_given){
		fprintf(stderr, "%s\n", "error: Key file needs to be provided");
		exit(1);
	}else{
		fd = fopen(filename,"r");
		char tmp;
		tmp = fgetc(fd);
		int ctr;
		ctr=0;
		while(tmp != EOF && tmp != '\n'){
			encrypted_key[ctr] = tmp;
			ctr++;
			tmp = fgetc(fd);
		}
		fclose(fd);
	}

	dest_ip = argv[optind];
	dest_port = argv[++optind];
	
	if(!is_acting_as_server){
		act_as_client(encrypted_key,dest_ip,atoi(dest_port));
	}else{
		act_as_server(encrypted_key,listen_port,dest_ip,atoi(dest_port));
	}
}