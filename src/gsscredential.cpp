#include "gsspp/gsscredential.h"
#include "gsspp/gssbuffer.h"
#include "gsspp/gssname.h"
#include "gsspp/gssexception.h"

GSSCredential::GSSCredential( const GSSName& name )
{
	// TODO: have a way to return actual time and actual mech

	OM_uint32 maj, min;
	maj = gss_acquire_cred( &min, name, GSS_C_INDEFINITE, 0, 0, &_credential, 0, 0 );

	if ( maj != GSS_S_COMPLETE )
		throw GSSException( maj, min, "gss_acquire_cred" );
}

GSSCredential::GSSCredential( const GSSName& name, const GSSBuffer& password )
{
    OM_uint32 maj, min;
    maj = gss_acquire_cred_with_password( &min, name, const_cast<GSSBuffer&>(password), GSS_C_INDEFINITE, 0, 0, &_credential, 0, 0 );

    if ( maj != GSS_S_COMPLETE )
        throw GSSException( maj, min, "gss_acquire_cred_with_password" );
}

void GSSCredential::clear()
{
	OM_uint32 min;
	gss_release_cred( &min, &_credential );
}

GSSName GSSCredential::inquire_name() const
{
    OM_uint32 maj, min;
    gss_name_t cred_gss_name = 0;
    maj = gss_inquire_cred(&min, _credential, &cred_gss_name, 0, 0, 0);

    if ( maj != GSS_S_COMPLETE )
        throw GSSException( maj, min, "gss_inquire_cred" );

    return GSSName(cred_gss_name, /*take_ownership*/true);
}
