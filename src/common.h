#define PORT 5556
#define SERVER "127.0.0.1"

#define PRINTX(x,y) if (y[0]!=0) printf(" -   %s %s\n", x, y)
#define PRINT_DN(X) PRINTX( "CN:", X.common_name); \
	PRINTX( "OU:", X.organizational_unit_name); \
	PRINTX( "O:", X.organization); \
	PRINTX( "L:", X.locality_name); \
	PRINTX( "S:", X.state_or_province_name); \
	PRINTX( "C:", X.country); \
	PRINTX( "E:", X.email)

static int print_info( GNUTLS_STATE state) {
const char *tmp;
CredType cred;
gnutls_DN dn;
const gnutls_datum* cert_list;
CertificateStatus status;
int cert_list_size = 0;

	tmp = gnutls_kx_get_name(gnutls_kx_get_algo( state));
	printf("- Key Exchange: %s\n", tmp);

	cred = gnutls_auth_get_type(state);
	switch(cred) {
		case GNUTLS_ANON:
			printf("- Anonymous DH using prime of %d bits\n",
			       gnutls_anon_client_get_dh_bits( state));
			break;
		case GNUTLS_X509PKI:
			cert_list = gnutls_x509pki_client_get_peer_certificate_list( state, &cert_list_size);
			status = gnutls_x509pki_client_get_peer_certificate_status( state);
			
			switch( status) {
			case GNUTLS_CERT_NOT_TRUSTED:
				printf("- Peer's X509 Certificate was NOT verified\n");
				break;
			case GNUTLS_CERT_EXPIRED:
				printf("- Peer's X509 Certificate was verified but is expired\n");
				break;
			case GNUTLS_CERT_TRUSTED:
				printf("- Peer's X509 Certificate was verified\n");
				break;
			case GNUTLS_CERT_NONE:
				printf("- Peer did not send any X509 Certificate.\n");
				break;
			case GNUTLS_CERT_INVALID:
				printf("- Peer's X509 Certificate was invalid\n");
				break;
			}
			
			if (cert_list_size > 0) {
				char digest[20];
				char serial[40];
				int digest_size = sizeof(digest), i;
				int serial_size = sizeof(serial);
				char printable[120];
				char* print;

				printf(" - Certificate info:\n");
				
				if ( gnutls_fingerprint( GNUTLS_DIG_MD5, &cert_list[0], digest, &digest_size) >= 0) {
					print = printable;
					for (i=0;i<digest_size;i++) {
						sprintf( print, "%.2x ", (unsigned char)digest[i]);
						print += 3;
					}
					printf(" - Certificate fingerprint: %s\n", printable);
				}

				if ( gnutls_x509pki_extract_certificate_serial( &cert_list[0], serial, &serial_size) >= 0) {
					print = printable;
					for (i=0;i<serial_size;i++) {
						sprintf( print, "%.2x ", (unsigned char)serial[i]);
						print += 3;
					}
					printf(" - Certificate serial number: %s\n", printable);
				}

				printf(" - Certificate version: #%d\n", gnutls_x509pki_extract_certificate_version( &cert_list[0]));

				gnutls_x509pki_extract_certificate_dn( &cert_list[0], &dn);
				PRINT_DN( dn);

				gnutls_x509pki_extract_certificate_issuer_dn( &cert_list[0], &dn);
				printf(" - Certificate Issuer's info:\n");
				PRINT_DN( dn);
			}
	}

	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(state));
	printf("- Version: %s\n", tmp);

	tmp = gnutls_compression_get_name(gnutls_compression_get_algo( state));
	printf("- Compression: %s\n", tmp);

	tmp = gnutls_cipher_get_name(gnutls_cipher_get_algo( state));
	printf("- Cipher: %s\n", tmp);

	tmp = gnutls_mac_get_name(gnutls_mac_get_algo( state));
	printf("- MAC: %s\n", tmp);

	return 0;
}
