package com.starburstdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.AESDecrypter;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.Header;
import io.trino.server.security.oauth2.ZstdCodec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkState;
import static io.trino.server.security.jwt.JwtUtil.newJwtParserBuilder;

public class Main
{
    private static String deserialize( SecretKey secretKey, String token )
            throws ParseException
    {
        try {
            JWEObject jwe = JWEObject.parse(token);
            jwe.decrypt(new AESDecrypter(secretKey));
            return jwe.getPayload().toString();
        }
        catch ( JOSEException e ) {
            throw new RuntimeException(e);
        }
    }

    public static CompressionCodec resolveCompressionCodec( Header<?> header)
            throws CompressionException
    {
        if (header.getCompressionAlgorithm() != null) {
            checkState(header.getCompressionAlgorithm().equals( ZstdCodec.CODEC_NAME), "Unknown codec '%s' used for token compression", header.getCompressionAlgorithm());
            return new ZstdCodec();
        }
        return null;
    }

    public static void main( String[] args )
    {
        Map<String, String> argsMap = new HashMap<>();
        for (String arg: args) {
            String[] parts = arg.split("=");
            argsMap.put(parts[0], parts[1]);
        }

        StringBuilder sb = new StringBuilder();

        if( ! argsMap.containsKey( "key" ) )
        {
            sb.append( "Missing parameter 'key'\n" );
        }
        if( ! argsMap.containsKey( "tokenfile" ) )
        {
            sb.append( "Missing parameter 'tokenfile'\n" );
        }
        if( ! sb.isEmpty() )
        {
            System.out.print( sb );
            System.exit( -1 );
        }

        String key = argsMap.get( "key" );
        String token = "";

        try
        {
            token = Files.readString( Paths.get( argsMap.get( "tokenfile" ) ) );
        }
        catch( IOException ex )
        {
            System.out.print( ex );
            System.exit( -2 );
        }

        var secretKey = new SecretKeySpec( Base64.getDecoder().decode(key), "AES");

        try
        {
            var parser = newJwtParserBuilder().setCompressionCodecResolver( Main::resolveCompressionCodec ).build();

            var claims = parser.parseClaimsJwt( deserialize( secretKey, token ) ).getBody();

            var expiration = claims.get("expiration_time", Date.class);

            System.out.println( "Expiration: " + expiration );
        }
        catch( ParseException ex )
        {
            System.out.print( ex );
            System.exit( -3 );
        }
    }
}
