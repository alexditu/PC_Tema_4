/*
 * my_dns_client.c
 *
 *  Created on: May 17, 2013
 *      Author:  Ditu Alexandru 323 CA
 *      Tema 4 PC
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include "dns_message.h"

/** conversie de tip: din string in int */
int getType (char *type_s) {
	int type = -1; //caz de eroare;

	if (strcmp (type_s, "A") == 0) {
		type = 1;
	}
	if (strcmp (type_s, "MX") == 0) {
		type = 15;
	}
	if (strcmp (type_s, "NS") == 0) {
		type = 2;
	}
	if (strcmp (type_s, "CNAME") == 0) {
		type = 5;
	}
	if (strcmp (type_s, "SOA") == 0) {
		type = 6;
	}
	if (strcmp (type_s, "TXT") == 0) {
		type = 16;
	}

	return type;

}

/* conversie de tip: din int in string */
void getTypeFromInt (int type, char *type_s) {

	if (type == 1) {
		strcpy (type_s, "A");
	}
	if (type == 15) {
		strcpy (type_s, "MX");
	}
	if (type == 2) {
		strcpy (type_s, "NS");
	}
	if (type == 5) {
		strcpy (type_s, "CNAME");
	}
	if (type == 6) {
		strcpy (type_s, "SOA");
	}
	if (type == 16) {
		strcpy (type_s, "TXT");
	}
}

/** decmprima un domain name (cazul in care sunt folositi pointeri) */
void decompress (char *m, int offset, char *str, int *len) {
	int i, j, no, k;

	i = offset;
	k = *len;

	int pointer = 0;

	while (m[i] != 0) {

		/* folosesc ca sa iau 2 octeti */
		unsigned int x;
		memcpy (&x, m + i, 2);
		x = ntohs (x);

		if (x >= 49152) {//pointer

			int off;
			/* aflu offsetul la care este labelul cautat */
			off = x - 49152; //sterg primii 2 biti: 1023 = 0011 1111 ... 11

			*len = k;
			decompress (m, off, str, &k);
			//pointer = 1;
			*len += 2;
			return;

		} else {
			no = m[i];
			i++;
			for (j = 0; j < no; j++) {

				str[k] = m[i];
				i++;
				k++;
			}
			str[k] = '.';
			k++;
		}
	}

	*len = k + 1;
	str[k] = '\0';
}

/* Aceasta functie primeste multi parametri si proceseaza toate informatiile
 * dintr-un RR. Nu este important de care RR este vorba, ci conteaza tipul
 * interogarii.
 */
int writeInfoType (char *buf, int offset, int type, int count, int rdlen,
					int rr_size,
					char *name, char *type_s, char *class, FILE *out) {

	if (count != 0) {

		/* daca este mesaj de tip A */
		if (type == 1) {

			int i = count;
			unsigned char ip_addr[4];
			int j;

			for (i = 0; i < count; i++) {
				for (j = 0; j < rdlen; j++) {
					memcpy (&ip_addr[j], buf + offset, 1);
					offset += 1;
				}

				fprintf (out, "%s %s %s %d.%d.%d.%d\n", name, class, type_s,
						ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);

				memset (ip_addr, 0, 4);

				offset += rr_size;
			}
			offset -= rr_size;

		}

		/* daca este mesaj de tip TXT */
		if (type == 16) {

			int i = count;
			unsigned char *data = malloc (sizeof (char) * rdlen);
			int j;

			for (i = 0; i < count; i++) {

				memcpy (data, buf + offset, rdlen);
				fprintf (out, "%s %s %s %s\n", name, class, type_s, data);

				offset += rr_size;
			}
			offset -= rr_size;

		}

		/* daca este mesaj de tip CNAME */
		if (type == 5) {

			char cname[255];
			int len = 0;

			decompress (buf, offset, cname, &len);

			offset += len;

			fprintf (out, "%s %s %s %s\n", name, class, type_s, cname);
		}

		/* daca este mesaj de tip NS */
		if (type == 2) {

			char domain[255];
			int len = 0;
			int i, j;


			for (i = 0; i < count; i++) {

				memset (domain, 0, 255);
				len = 0;

				decompress (buf, offset, domain, &len);

				offset += len + rr_size;

				fprintf (out, "%s %s %s %s\n", name, class, type_s, domain);
			}
			offset -= rr_size;

		}

		/* daca este mesaj de tip MX */
		if (type == 15) {

			int preference;
			char exchange[255];
			int len = 0;
			int i;

			for (i = 0; i < count; i++) {

				memcpy (&preference, buf + offset, 2);
				preference = ntohs (preference);
				offset += 2;

				memset (exchange, 0, 255);
				len = 0;

				decompress (buf, offset, exchange, &len);

				fprintf (out, "%s %s %s %d %s\n", name, class,
						type_s, preference, exchange);

				offset += len + rr_size;
			}
			offset -= rr_size;

		}

		/* daca este mesaj de tip SOA */
		if (type == 6) {

			char mname[255];
			char rname[255];
			int m_len = 0, r_len = 0;
			int serial, refresh, retry, expire;
			int i;

			for (i = 0; i < count; i++) {
				memset (mname, 0, 255);
				memset (rname, 0, 255);
				m_len = r_len = serial = refresh = retry = expire = 0;

				decompress (buf, offset, mname, &m_len);
				offset += m_len;

				decompress (buf, offset, rname, &r_len);
				offset += r_len;

				memcpy (&serial, buf + offset, sizeof (int));
				serial = ntohs (serial);
				offset += sizeof (int);

				memcpy (&refresh, buf + offset, sizeof (int));
				refresh = ntohs (refresh);
				offset += sizeof (int);

				memcpy (&retry, buf + offset, sizeof (int));
				refresh = ntohs (retry);
				offset += sizeof (int);

				memcpy (&expire, buf + offset, sizeof (int));
				refresh = ntohs (expire);
				offset += sizeof (int);

				fprintf (out, "%s %s %s %s %s %d %d %d %d\n",
						name, type_s, class, mname, rname, serial, refresh,
						retry, expire);

				offset += rr_size;
			}
			offset -= rr_size;
		}

	}

	return offset;


}


/* Aceasta functie incepe parsarea mesajului de la serverul DNS
 * Extrage numele, tipul si domeniul, iar apoi in functie de care campuri sunt
 * active (Answer, Authority si Additional), apeleaza functia writeInfoType.
 *
 */
void writeRRInfo (char *buf, FILE *out) {

	char name[255];
	char qname[255];
	int qname_len = 0;
	int name_len = 0;
	int offset;
	int rr_size;
	dns_header_t header;


	/* extrag informatii legate de header */
	offset = sizeof (dns_header_t);
	memcpy (&header, buf, offset);

	/* aflu care este QNAME, ca sa stiu offsetul pentru RR */
	decompress (buf, offset, qname, &qname_len);

	offset += qname_len + sizeof (dns_question_t);

	char type_s[5];
	char class[2];
	int type, rdlen;
	strcpy (class, "IN");

	/* in functie de type, parsez RDATA*/

	int ancount = ntohs (header.ancount);
	int nscount = ntohs (header.nscount);
	int arcount = ntohs (header.arcount);

	if (ancount != 0) {

		fprintf (out, ";;ANSWER SECTION\n");

		/* mai intai iau din RR: numele, tipul si clasa: */
		memset (name, 0, 255);
		decompress (buf, offset, name, &name_len);

		offset += name_len;
		rr_size = name_len + sizeof (dns_rr_t) - 2;

		/* extrag rrtype si rrclass */
		dns_rr_t rr;
		memcpy (&rr, buf + offset, sizeof (dns_rr_t) - 2);

		offset += sizeof (dns_rr_t) - 2; //pune 2 octeti in plus

		/* fac conversie: transform rtype si rclass in stringuri */
		getTypeFromInt (ntohs(rr.type), type_s);

		type = ntohs (rr.type);
		rdlen = ntohs(rr.rdlength);

		offset = writeInfoType (buf, offset, type, ancount, rdlen,
							rr_size,
							name, type_s, class, out);
	}



	if (nscount != 0) {

		fprintf (out, "\n;;AUTHORITY SECTION\n");


		/* mai intai iau din RR: numele, tipul si clasa: */
		name_len = 0;
		decompress (buf, offset, name, &name_len);


		offset += name_len;
		rr_size = name_len + sizeof (dns_rr_t) - 2;

		/* extrag rrtype si rrclass */
		dns_rr_t rr;
		memcpy (&rr, buf + offset, sizeof (dns_rr_t) - 2);

		offset += sizeof (dns_rr_t) - 2; //pune 2 octeti in plus

		/* fac conversie: transform rtype si rclass in stringuri */
		getTypeFromInt (ntohs(rr.type), type_s);

		type = ntohs (rr.type);
		rdlen = ntohs(rr.rdlength);

		offset = writeInfoType (buf, offset, type, nscount, rdlen,
							rr_size,
							name, type_s, class, out);

	}


	if (arcount != 0) {

		fprintf (out, "\n;;ADDITIONAL SECTION\n");

		/* mai intai iau din RR: numele, tipul si clasa: */
		memset (name, 0, 255);
		name_len = 0;
		decompress (buf, offset, name, &name_len);

		offset += name_len;
		rr_size = name_len + sizeof (dns_rr_t) - 2;

		/* extrag rrtype si rrclass */
		dns_rr_t rr;
		memset (&rr, 0, sizeof (dns_rr_t) - 2);

		memcpy (&rr, buf + offset, sizeof (dns_rr_t) - 2);

		offset += sizeof (dns_rr_t) - 2; //pune 2 octeti in plus

		type = ntohs (rr.type);
		rdlen = ntohs(rr.rdlength);

		/* fac conversie: transform rtype si rclass in stringuri */
		getTypeFromInt (ntohs(rr.type), type_s);

		offset = writeInfoType (buf, offset, type, ancount, rdlen,
							rr_size,
							name, type_s, class, out);
	}
}

/* Aceasta functie primeste un fisier de tipul dns_servers.conf, si extrage
 * din acesta (la fiecare apel) cate o adresa ip (sarind peste comentarii si
 * linii goale). Cand se ajunge la sfarsit, intoarce -1.
 */
int getDnsFromFile (FILE *fld, char *ip) {
	char buffer[100];
	char *p, *q;

	memset (ip, 0, 20);
	q = fgets (buffer, 100, fld);
	strcpy (ip, q);

	while (q != NULL) {

		p = strtok (buffer, " .\n");
		if ((p != NULL) && (strcmp (p, "#") != 0)) {

			/* am gasit o adresa ip */
			ip[strlen(ip) - 1] = '\0';

			return 1;
		}

		memset (buffer, 0, 100);
		q = fgets (buffer, 100, fld);

		if (q == NULL) {

			return -1;
		}
		strcpy (ip, q);
	}

	return -1;
}



int main(int argc, char **argv) {

	if (argc < 3) {
		printf ("Error: too few arguments!\n");
		return -1;
	}

	/* type si type_s specifica tipul interogarii: o variabila este folosita
	 * pentru a retine tipul in format string (pentru afisare), iar a II -a
	 * in diferite functii.
	 */
	char type_s[5];
	int type;
	char domain_name[255];
	char domain_name_c[255];

	/* toate adresele ip din fisierul dns_servers.conf le retin intr-un vector
	 * de adrese, pentru a le putea folosi pe rand, in cazul in care un server
	 * nu functioneaza
	 */
	char ip[10][20];
	int ip_no = 0;

	int sfd;
	struct sockaddr_in dns_server;

	dns_header_t header;
	dns_question_t question;

	/* parsare argumente: nume domeniu si tip */
	strcpy (domain_name, argv[1]);
	strcpy (domain_name_c, argv[1]);
	strcpy (type_s, argv[2]);

	/* transformare tip, din string in int-ul corespunzator */
	type = getType (type_s);

	if (type < 0) {
		printf ("Error: type unknown! Exiting ... \n");
		return -1;
	}

	/* incarc toate ip-urile din lista dns_servers.conf */
	FILE *fp = fopen ("dns_servers.conf", "r");

	while (getDnsFromFile (fp, ip[ip_no]) != -1) {
		ip_no ++;
	}

	/* creare header */
	memset (&header, 0, sizeof(header));

	header.id = htons(1992);
	header.rd = 1;
	header.tc = 0;
	header.aa = 0;
	header.opcode = 0; //4
	header.qr = 0;

	header.rcode = 0;
	header.z = 0; //reserved for further use
	header.ra = 0; //setat la raspuns

	header.qdcount = htons(1);
	header.ancount = 0;
	header.nscount = 0;
	header.arcount = 0;

	/* creare QNAME din domain_name, adica transform o adresa de forma:
	 * www.google.com in una de forma 3www6google3com
	 */
	char *p;
	int i, j;
	int name_len = strlen (domain_name) + 2;

	char *qname = malloc (name_len * sizeof (char));

	p = strtok (domain_name, ".");
	j = 0;

	while (p != NULL) {

		i = strlen (p);
		qname[j] = i;
		j++;
		strcpy (qname + j, p);
		j += i;

		p = strtok (NULL, ".");
	}
	qname[j] = 0;

	/* creare structura question */
	question.qtype = htons(type);
	question.qclass = htons(1);

	/* creare mesaj: header + question */
	char *message;
	int msg_len = sizeof (header) + sizeof (dns_question_t) + name_len;
	message = malloc (sizeof (char) * msg_len);

	memcpy (message, &header, sizeof (header));
	memcpy (message + sizeof (header), qname, name_len);
	memcpy (message + sizeof (header) + name_len, &question, sizeof (dns_question_t));


	/*Deschidere socket*/
	sfd = socket(AF_INET, SOCK_DGRAM, 0);

	int count = -1;
	char buf[512];
	socklen_t size;
	struct sockaddr_in from_dns_srv;


	/* structura pentru timeout in receive (astept maxim 3 secunde) */
	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;

	setsockopt (sfd, SOL_SOCKET, SO_RCVTIMEO, (char*) &tv, sizeof (struct timeval));

	int got_reply = 0;
	for (i = 0; i < ip_no; i++) {

		/*Setare struct sockaddr_in pentru a specifica unde trimit datele*/
		dns_server.sin_family = AF_INET;
		dns_server.sin_port = htons(53);
		inet_aton(ip[i], (struct in_addr *)&dns_server.sin_addr.s_addr);

		int cn = connect (sfd, (struct sockaddr *) &dns_server, sizeof (struct sockaddr_in));
		if (cn < 0) {
			printf ("Error in connect\n");
		}

		count = sendto(sfd, message, msg_len, 0, (struct sockaddr* ) &dns_server, sizeof(struct sockaddr_in));

		if (count < 0) {

			printf ("Error in sending message\n");
			continue;

		}else{

			printf ("Sent querry, count: %d\n", count);
			got_reply = 1;
		}

		if (got_reply == 1) {

			count = recvfrom (sfd, buf, 512, 0, (struct sockaddr*) &from_dns_srv , &size);

			if (count < 0) {

				printf ("Error: recv count: %d\n", count);
				got_reply = 0;

			} else {

				printf ("Recv succesfuly, count: %d\n", count);
				got_reply = 2;
				break;
			}
		}
	}

	if (got_reply != 2) {

		printf ("Fatal Error: No reply from DNS servers. Exiting ...\n");
		return 0;
	}


	FILE *out;

	/* deschid fisierul de scriere */
	out = fopen ("logfile", "a+");

	/* scriu in fisier numele serverului de DNS si tipul interogarii */
	fprintf (out, "; %s - %s %s\n", ip[i], domain_name_c, type_s);

	/* parsare RR */

	writeRRInfo (buf, out);

	fprintf (out, "\n\n");

	fclose (out);
	close (sfd);
	fclose (fp);
	return 0;
}
