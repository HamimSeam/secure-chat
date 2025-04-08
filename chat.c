#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "util.h"
#include <limits.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */
static int security_mode = 1;
static unsigned char dh_shared_key[256] = {0};
unsigned char hmac_buf[2048];

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })


typedef enum { SERVER, CLIENT } Role;
/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	// read in appropiate RSA keys
	FILE *fp = fopen("keys/server/private.pem", "rb");
	EVP_PKEY *rsa_sk_server = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	printf("\nServer successfully read server private RSA key.\n");

	fp = fopen("keys/client/public.pem", "rb");
	EVP_PKEY *rsa_pk_client = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);	

	printf("Server successfully read client public RSA key.\n");

	// serialize the mpz DH key to send in over channel
	int fds[2];
	if (pipe(fds) == -1) {
		perror("Error creating pipe");
		exit(EXIT_FAILURE);
	}

	// generate DH keys
	init("params");
	mpz_t dh_sk_server, dh_pk_server;
	mpz_init(dh_sk_server);
	mpz_init(dh_pk_server);
	dhGen(dh_sk_server, dh_pk_server);

	printf("Server successfully generated DH key pair.\n");

	// sign DH public key
    size_t sig_len = EVP_PKEY_size(rsa_sk_server);
    unsigned char *signature = OPENSSL_malloc(sig_len); 

    generate_signature(rsa_sk_server, dh_pk_server, 
		&signature, &sig_len, fds);
	
	printf("Server successfully generated signature of DH public key.\n");
	size_t dh_pk_server_len = serialize_mpz(fds[1], dh_pk_server);
	
	// write [ key_len, key, sig_len, signature ] to the buf
	char buf[2048];
	if (memcpy(buf, &dh_pk_server_len, sizeof(size_t)) == NULL) {
		perror("Error copying dh_pk_server_len to buffer");
		close(fds[0]);
		return -1;
	}

	ssize_t bytes_read = read(fds[0], buf + sizeof(size_t), dh_pk_server_len);
	if (bytes_read != dh_pk_server_len) {
		perror("Error reading from pipe");
		close(fds[0]);
		OPENSSL_free(signature);
		return -1;
	}	

	if (memcpy(buf + sizeof(size_t) + dh_pk_server_len, &sig_len, sizeof(size_t)) == NULL) {
		perror("Error copying sig_len to buffer");
		close(fds[0]);
		OPENSSL_free(signature);
		return -1;
	}


	if (memcpy(buf + dh_pk_server_len + 2 * sizeof(size_t), signature, sig_len) == NULL) {
		perror("Error copying signature to buffer");
		close(fds[0]);
		OPENSSL_free(signature);
		return -1;
	}

	printf("Server successfully saved key and signature to buffer\n");

	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */

	// do the actual key exchange
	unsigned char recv_buf[2048];
	if (recv(sockfd, recv_buf, 2048, 0) == -1) {
		error("ERROR receiving signature from client.\n");
	}

	printf("\nServer successfully received signature!\n");

	mpz_t dh_pk_client;
	mpz_init(dh_pk_client);

	unsigned char* signature_client = NULL;
	size_t sig_len_client;

	extract_signature(recv_buf, dh_pk_client, &signature_client, &sig_len_client, fds);
	int verify_ok = verify_signature(rsa_pk_client, dh_pk_client, signature_client, sig_len_client, fds);
	if (verify_ok == 1) {
		printf("Server successfully verified client signature!.\n");
	}
	else if (verify_ok == -1) {
		printf("Error on verification\n");
	}
	else {
		printf("Signature verification failed.\n");
	}

	if (send(sockfd, buf, 2048, 0) == -1) {
		error("ERROR sending signature from server.");
	}

	dhFinal(dh_sk_server, dh_pk_server, dh_pk_client, dh_shared_key, 256);

	close(fds[0]);
	close(fds[1]);
	security_mode = 0;
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	// read in appropiate RSA keys
	FILE *fp = fopen("keys/client/private.pem", "rb");
	EVP_PKEY *rsa_sk_client = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	printf("\nClient successfully read client private RSA key.\n");

	fp = fopen("keys/server/public.pem", "rb");
	EVP_PKEY *rsa_pk_server = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);	

	printf("Client successfully read server public RSA key.\n");

	// generate DH keys
	init("params");
	mpz_t dh_sk_client, dh_pk_client;
	mpz_init(dh_sk_client);
	mpz_init(dh_pk_client);
	if (dhGen(dh_sk_client, dh_pk_client) != 0) {
		printf("Error in key generation.\n");
	}

	printf("Client successfully generated DH key pair.\n");

	// serialize the mpz DH key to send over channel
	int fds[2];
	if (pipe(fds) == -1) {
		perror("Error creating pipe");
		exit(EXIT_FAILURE);
	}

	// sign DH public key
    size_t sig_len = EVP_PKEY_size(rsa_sk_client);
    unsigned char *signature = OPENSSL_malloc(sig_len); 
	
	if (generate_signature(rsa_sk_client, dh_pk_client, &signature, &sig_len, fds) != 0) {
		fprintf(stderr, "Error generating signature\n");
		return -1;
	}

	printf("Client successfully generated signature of DH public key.\n");

	size_t dh_pk_client_len = serialize_mpz(fds[1], dh_pk_client);
	
	// write [ key_len, key, sig_len, signature ] to the buf
	char buf[2048];
	if (memcpy(buf, &dh_pk_client_len, sizeof(size_t)) == NULL) {
		perror("Error copying dh_pk_client_len to buffer");
		close(fds[0]);
		return -1;
	}

	ssize_t bytes_read = read(fds[0], buf + sizeof(size_t), dh_pk_client_len);
	
	if (bytes_read != dh_pk_client_len) {
		perror("Error reading from pipe");
		close(fds[0]);
		OPENSSL_free(signature);
		return -1;
	}	

	if (memcpy(buf + sizeof(size_t) + dh_pk_client_len, &sig_len, sizeof(size_t)) == NULL) {
		perror("Error copying sig_len to buffer");
		close(fds[0]);
		OPENSSL_free(signature);
		return -1;
	}


	if (memcpy(buf + dh_pk_client_len + 2 * sizeof(size_t), signature, sig_len) == NULL) {
		perror("Error copying signature to buffer");
		close(fds[0]);
		OPENSSL_free(signature);
		return -1;
	}

	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	/* at this point, should be able to send/recv on sockfd */

	if (send(sockfd, buf, 2048, 0) == -1) {
		error("ERROR sending signature");
	}

	unsigned char recv_buf[2048];
	if (recv(sockfd, recv_buf, 2048, 0) == -1) {
		error("ERROR receiving signature from client.\n");
	}

	printf("\nServer successfully received signature!\n");

	mpz_t dh_pk_server;
	mpz_init(dh_pk_server);

	unsigned char* signature_server = NULL;
	size_t sig_len_server;

	extract_signature(recv_buf, dh_pk_server, &signature_server, &sig_len_server, fds);

	int verify_ok = verify_signature(rsa_pk_server, dh_pk_server, signature_server, sig_len_server, fds);
	if (verify_ok == 1) {
		printf("Client successfully verified server signature!.\n");
	}
	else if (verify_ok == -1) {
		printf("Error on verification\n");
	}
	else {
		printf("Client failed to verify signature.\n");
	}

	dhFinal(dh_sk_client, dh_pk_client, dh_pk_server, dh_shared_key, 256);

	close(fds[0]);
	close(fds[1]);
	security_mode = 0;
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */

	// security_mode = 0; //prevent displaying handshake/hmac contents on GUI
	unsigned int hmac_len = 0;
	unsigned char* hmac = generate_hmac(dh_shared_key, 256, (const unsigned char*)message, (int)len, &hmac_len);
	bundle_hmac(len, message, (size_t)hmac_len, hmac, hmac_buf);

	if (send(sockfd, hmac_buf, 2*sizeof(size_t) + len + hmac_len, 0) == -1) {
		printf("Error on sending (message, hmac) pair\n");
	}

	// if (send(sockfd,hmac_buf,hmac_len,0) == -1) {
	// 	printf("Error on sending (message, hmac) pair\n");
	// }

	// security_mode = 1; //allow displaying messages on GUI

	ssize_t nbytes;
	if ((nbytes = send(sockfd,hmac_buf,2 * sizeof(size_t) + len + hmac_len,0)) == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */

	 if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		// if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
		// 	error("recv failed");
		// if (nbytes == 0) {
		// 	/* XXX maybe show in a status message that the other
		// 	 * side has disconnected. */
		// 	return 0;
		// }

		if ((nbytes = recv(sockfd,hmac_buf,2048,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}

		size_t len;
		size_t hmac_len;
		unsigned char hmac[256];
		extract_hmac(&len, msg, &hmac_len, hmac, hmac_buf);
		if (verify_hmac(dh_shared_key, 256, msg, (int)len, hmac, (int)hmac_len) != 1) {
			printf("Error on verifying HMAC\n");
		}
		else {
			printf("HMAC successfully verified!\n");
		}

		if (!security_mode) {
			char* m = malloc(maxlen+2);
			memcpy(m,msg,len);
			if (m[len-1] != '\n')
				m[len++] = '\n';
			m[len] = 0;
			g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
		}
	}
	return 0;
}
