# mp-lemon-builder
Microprofile project builder with JWT authentication.

Esta aplicación está basada en dos proyectos. El generador de JWT publicado por Victor Orozco: https://vorozco.com/blog/2019/2019-10-02-MicroProfile-JWT-Token-Provider-Servlet.html, y http://jwtenizr.sh/ de Adam Bien.

El objetivo de esta aplicación es generar dos proyectos web: una de ellas se encargará de proveer un token, validando la autenticación usando el Realm del contenedor donde esté ejecutándose (en esta versión aún es solo Payara); y la segunda aplicación es quien tiene endpoints asegurados por roles del token provisto.

Para ver la ayuda, agregar el parámetro `--help`

        --group-id      Grupo del proyecto (Default value:apuntesdejava.com)
        --project-name  Nombre del proyecto  (Default value:example-project)
        --version       Versión del proyecto (Default value:1.0.0-SNAPSHOT)
        --web-app       Aplicación base que estará asegurada  (Default value:web-app)
        --jwt-provider  Aplicación web que generara token (Default value:jwt-provider)
        --realm-name    Realm configurado en el contenedor (Default value:realm-example)
        --header-key    Clave de la cabecera del token (Default value:header-key-example)
        --issuer        Issuer del JWT (Default value:http://example.com)
        --expires       Tiempo de expiración (Default value:100000)
        --roles Lista de roles a considerar (Default value:admin,user)
        --output-project        Ubicación de la ruta a generar el proyecto (Default value:output-project)
        
## Ejecutable
Esta es la aplicación ejecutable desde la línea de comandos
[mplemonbuilder.jar](mplemonbuilder.jar)

## Una breve explicación en el blog
http://bit.ly/2rBX5Wb

## En Acción        
https://youtu.be/AafDYt4uF0M

## Registro de Cambios
### 0.0.2:
- Incluye un banner bonito.
- Se crean las carpetas jwt-provider y web-app con el nombre indicado en los argumentos del programa.
- Si hay algún parámetro que tiene valor indicado en la línea de comandos, se le pedirá via consola de manera iteractiva.
- Antes de generar los proyectos, se muestran los valores ingresos y se pide confirmación de los valores indicados.
