#include "ssl_shell.h"

#include <stdlib.h>
#include <string.h>
//---------------------------------------------------------------------------
int _ssl_err_hdlr(SSL *s, BIO *b, int fd, int err_code)
{
	int pending;

	if (err_code <= 0)
	{
		switch (SSL_get_error(s, err_code))
		{
		case SSL_ERROR_NONE: //0
		case SSL_ERROR_SSL:  // 1
			//don't break, flush data first

		case SSL_ERROR_WANT_READ: // 2
		case SSL_ERROR_WANT_WRITE: // 3
		case SSL_ERROR_WANT_X509_LOOKUP:  // 4
			pending = BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL);
			if (pending > 0)
			{
				char *buf;

				// 这里可以马上发送出去, 也可以先存起来推迟再发送
				// (所谓推迟只是把数据集中)
				buf = new char[pending];
				if (buf)
				{
					BIO_read(b, buf, pending);

					XYTCPSend((SOCKET)fd, buf, pending, 0);

					delete[] buf;
				}
			}
			break;
		case SSL_ERROR_ZERO_RETURN: // 5
		case SSL_ERROR_SYSCALL: //6
		case SSL_ERROR_WANT_CONNECT: //7
		case SSL_ERROR_WANT_ACCEPT: //8
		default:
			break;
		}
	}
	return(err_code);
}
int _ssl_handshake(struct _ssl_session *psession, int fd)
{
	SSL *s = psession->s;
	BIO *b = psession->b1;
	int err_code;

	err_code = SSL_do_handshake(s);
	_ssl_err_hdlr(s, b, fd, err_code);
	return(err_code);
}

int _ssl_session_initialize(struct _ssl_session *psession, SSL_CTX *ctx, int c)
{
	SSL *s;
	BIO *b;
	BIO *b1;

	psession->s = NULL;
	psession->b = NULL;
	psession->b1 = NULL;

	if (s = SSL_new(ctx))
	{
		if (c)
		{
			SSL_set_connect_state(s);
		}
		else
		{
			SSL_set_accept_state(s);
		}

		BIO_new_bio_pair(&b, 0, &b1, 0);

		SSL_set_bio(s, b, b);

		psession->s = s;
		psession->b = b;
		psession->b1 = b1;
	}
	return(c);
}
void _ssl_session_uninitialize(struct _ssl_session *psession)
{
	SSL **s;
	BIO **b;

	s = &psession->s;
	if (*s)
	{
		//
	}

	b = &psession->b;
	if (*b)
	{
		BIO_free(*b);
		*b = NULL;
	}
	b = &psession->b1;
	if (*b)
	{
		BIO_free(*b);
		*b = NULL;
	}
}

int _ssl_read(struct _ssl_session *psession, int fd,
	const void *src, unsigned int src_len,
	void *dst, unsigned int dst_len,
	int *err_code, int *connected)
{
	SSL *s = psession->s;
	BIO *b = psession->b1;
	int flag = 1;

	*err_code = 0;

	if (src_len)
	{
		BIO_write(b, src, src_len);

		*connected = 0;

		if (!SSL_is_init_finished(s))
		{
			*err_code = _ssl_handshake(psession, fd);

			if (*connected = *err_code == 1)
			{
				*err_code = 0;
			}

			// 无论对不对, 都不继续了, 要运行两次
		}
		else
		{
			*connected = 1;
		}
	}

	if (*err_code == 0)
	{
		*err_code = SSL_read(s, dst, dst_len);
		if (*err_code <= 0 && SSL_ERROR_SSL == SSL_get_error(s, *err_code))
		{
			unsigned long e = ERR_get_error();
			printf("SSL read error: %s\n", ERR_error_string(e, NULL));
			printf("dst_len %d, err_code %d, press\r\n", dst_len, *err_code);
			getchar();
		}
		printf("dst_len %d, err_code %d, error %d\r\n", dst_len, *err_code, *err_code <= 0 ? SSL_get_error(s, *err_code) : 0);
		_ssl_err_hdlr(s, b, fd, *err_code);
	}
	return(0);
}
int _ssl_write(struct _ssl_session *psession, int fd,
	const void *buf, unsigned int len)
{
	SSL *s = psession->s;
	BIO *b = psession->b1;
	char *_buf;
	union
	{
		int pending;
		int err_code;
	};

	do
	{
		//this should give me something to write to client
		err_code = SSL_write(s, buf, len);
		WCHAR debugtext[256];
		wsprintf(debugtext, L"SSL_write len %d, err_code %d\r\n", len, err_code);
		OutputDebugString(debugtext);
		if (err_code > 0)
		{
			_buf = (char *)buf;
			_buf += err_code;
			buf = (const void *)_buf;
			len -= err_code;

			if ((pending = BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL)) > 0)
			{
				char *buf;

				// 这里可以马上发送出去, 也可以先存起来推迟再发送
				// (所谓推迟只是把数据集中)
				buf = new char[pending];
				if (buf)
				{
					err_code = BIO_read(b, buf, pending);

					XYTCPSend((SOCKET)fd, buf, pending, 0);

					delete[] buf;
				}
			}
		}
		else
		{
			wsprintf(debugtext, L"SSL_write SSL_get_error %d\r\n", SSL_get_error(s, err_code));
			OutputDebugString(debugtext);
		}
	} while (err_code > 0 && len);

	return(err_code);
}

void ssl_info_callback(const SSL *ssl, int where, int ret) {
	const char *state_str = SSL_state_string_long(ssl);
	const char *where_str = NULL;

	if (where & SSL_CB_LOOP) {
		where_str = "LOOP";
	}
	else if (where & SSL_CB_HANDSHAKE_START) {
		where_str = "HANDSHAKE_START";
	}
	else if (where & SSL_CB_HANDSHAKE_DONE) {
		where_str = "HANDSHAKE_DONE";
		printf("✅ TLS handshake done: version=%s, cipher=%s\n",
			SSL_get_version(ssl), SSL_get_cipher(ssl));
	}
	else if (where & SSL_CB_READ) {
		where_str = "READ";
	}
	else if (where & SSL_CB_WRITE) {
		where_str = "WRITE";
	}
	else if (where & SSL_CB_ALERT) {
		where_str = (where & SSL_CB_READ) ? "ALERT_READ" : "ALERT_WRITE";
		printf("⚠️  TLS alert: %s: %s\n",
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret));
	}
	else {
		where_str = "UNKNOWN";
	}

	printf("[SSL %s] %s\n", where_str, state_str);
}

void _ssl_initialize(struct _ssl_shell *pshell)
{
	SSL_CTX *ctx;

	// 初始化 openssl 库
	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

	ERR_clear_error();
	//

	//pshell->ctx0 = ctx = SSL_CTX_new(TLS_method());
	pshell->ctx0 = ctx = SSL_CTX_new(TLS_server_method());
	if (ctx)
	{
		//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
		//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
		SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

		SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, 
			SSL_MODE_AUTO_RETRY |
			SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			SSL_MODE_ENABLE_PARTIAL_WRITE, 
			NULL);

		SSL_CTX_ctrl(ctx, SSL_CTRL_MODE,
			SSL_MODE_RELEASE_BUFFERS,
			NULL);

		// 设置 cipher（TLS 1.2）
		SSL_CTX_set_cipher_list(ctx,
			"ECDHE-RSA-AES128-GCM-SHA256:"
			"ECDHE-RSA-AES256-GCM-SHA384");

		// 设置 TLS 1.3 cipher（OpenSSL >= 1.1.1）
		SSL_CTX_set_ciphersuites(ctx,
			"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");

		SSL_CTX_set_info_callback(ctx, ssl_info_callback);

		//// 设置 cipher suite（确保同时支持 RSA 和 RSA-PSS）
		//SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256");
		//// 设置 signature algorithms（支持 RSA 和 RSA-PSS）
		//SSL_CTX_set1_sigalgs_list(ctx, "rsa_pss_rsae_sha256:rsa_pkcs1_sha256");
	}

	pshell->ctx1 = ctx = SSL_CTX_new(TLS_client_method());
	if (ctx)
	{
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

		//// 设置 cipher suite（确保同时支持 RSA 和 RSA-PSS）
		//SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256");
		//// 设置 signature algorithms（支持 RSA 和 RSA-PSS）
		//SSL_CTX_set1_sigalgs_list(ctx, "rsa_pss_rsae_sha256:rsa_pkcs1_sha256");
	}
}
void _ssl_uninitialize(struct _ssl_shell *pshell)
{
	SSL_CTX **ctx;

	ctx = &pshell->ctx0;
	if (*ctx)
	{
		SSL_CTX_up_ref(*ctx);
		*ctx = NULL;
	}

	ctx = &pshell->ctx1;
	if (*ctx)
	{
		SSL_CTX_up_ref(*ctx);
		*ctx = NULL;
	}
}

//Need to enhance
int __tls_verify_peer(int ok, X509_STORE_CTX* ctx)
{
	return 1;
}
int _ssl_inhale(SSL_CTX *ctx, 
	const char *cert_file, const char *key_file, const char *str)
{
	int r;

	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "❌ Failed to load certificate\n");
		ERR_print_errors_fp(stderr);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "❌ Failed to load private key\n");
		ERR_print_errors_fp(stderr);
	}

	//TODO: Change this later, no hardcoding 
#define CIPHERS    "ALL:!EXPORT:!LOW"
	//r = pois->p_SSL_CTX_set_cipher_list(ctx, str);
	if (0 && r == 1)
	{
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, __tls_verify_peer);

		printf("SSL_CTX_set_verify\r\n");
		r = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
		if (r == 1)
		{
			printf("SSL_CTX_use_certificate_file\r\n");
			r = SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
			if (r == 1)
			{
				printf("SSL_CTX_use_PrivateKey_file\r\n");
				r = SSL_CTX_check_private_key(ctx);
			}
		}
	}

	return(r);
}
//---------------------------------------------------------------------------