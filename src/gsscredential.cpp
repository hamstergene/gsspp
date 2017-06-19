#include "gsspp/gsscredential.h"
#include "gsspp/gssbuffer.h"
#include "gsspp/gssname.h"
#include "gsspp/gssexception.h"

GSSName GSSCredential::inquire_name() const
{
    OM_uint32 maj, min;
    gss_name_t cred_gss_name = 0;
    maj = gss_inquire_cred(&min, _credential, &cred_gss_name, 0, 0, 0);

    if ( maj != GSS_S_COMPLETE )
        throw GSSException( maj, min, "gss_inquire_cred" );

    return GSSName(cred_gss_name, /*take_ownership*/true);
}

void GSSCredentialHolder::acquire( const GSSName& name, GSSMechList const& desired_mechs )
{
	clear();

	OM_uint32 maj, min;
    maj = gss_acquire_cred( &min, name, GSS_C_INDEFINITE, desired_mechs.empty() ? GSS_C_NO_OID_SET : const_cast<GSSMechList&>(desired_mechs), 0, &_credential, 0, 0 );

	if ( maj != GSS_S_COMPLETE )
		throw GSSException( maj, min, "gss_acquire_cred" );
}

void GSSCredentialHolder::acquire_with_password( const GSSName& name, const GSSBuffer& password, GSSMechList const& desired_mechs )
{
    clear();

    OM_uint32 maj, min;
    maj = gss_acquire_cred_with_password( &min, name, const_cast<GSSBuffer&>(password), GSS_C_INDEFINITE, desired_mechs.empty() ? GSS_C_NO_OID_SET : const_cast<GSSMechList&>(desired_mechs), 0, &_credential, 0, 0 );

    if ( maj != GSS_S_COMPLETE )
        throw GSSException( maj, min, "gss_acquire_cred_with_password" );
}

void GSSCredentialHolder::clear()
{
    if (_credential != GSS_C_NO_CREDENTIAL)
    {
    	OM_uint32 min;
    	gss_release_cred( &min, &_credential );
        _credential = GSS_C_NO_CREDENTIAL;
    }
}
