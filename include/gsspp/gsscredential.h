#ifndef __GSSCREDENTIAL_H__
#define __GSSCREDENTIAL_H__


#include "gssapi_includes.h"
#include "gsspp/gssmech.h"

class GSSBuffer;
class GSSName;

class GSSCredential
{
 public:
	GSSCredential() : _credential( GSS_C_NO_CREDENTIAL ) {}
	GSSCredential( const GSSCredential& other ) : _credential(other._credential) {}
	GSSCredential( gss_cred_id_t cred ) : _credential( cred ) {}

	GSSCredential& operator = ( gss_cred_id_t cred ) { _credential = cred; return *this; }
	GSSCredential& operator = ( const GSSCredential& other ) { _credential = other._credential; return *this; }

	// void clear() { _credential = GSS_C_NO_CREDENTIAL; }
	GSSName inquire_name() const;


	operator gss_cred_id_t () { return _credential; }

 protected:
	gss_cred_id_t _credential;
};

class GSSCredentialHolder : public GSSCredential
{
 public:
	GSSCredentialHolder() : GSSCredential( GSS_C_NO_CREDENTIAL ) {}
	GSSCredentialHolder( const GSSCredentialHolder& ) = delete;
	GSSCredentialHolder( GSSCredentialHolder&& ) = delete;

	void acquire( const GSSName& name, GSSMechList const& desired_mechs = GSSMechList() );
	void acquire_with_password( const GSSName& name, const GSSBuffer& password, GSSMechList const& desired_mechs = GSSMechList() );

	~GSSCredentialHolder() { clear(); }

	void clear();

	gss_cred_id_t* operator &() { clear(); return &_credential; }
};

#endif // __GSSCREDENTIAL_H__
