import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;


/**
 * Aplicaciones Telemáticas para la Administración
 * 
 * Este programa debe leer el nombre y NIF de un usuario del DNIe, formar el identificador de usuario y autenticarse con un servidor remoto a través de HTTP 
 * @author Juan Carlos Cuevas Martínez
 */
public class Main {
    
    /**
     * 
     * @param urlpost url del recurso al que se enviaran las credenciales por POST
     * @param username nombre de usuario
     * @param password contraseña
     * @return Nos devuelve la respuesta del servidor
     */
    public static String enviarCredencialesPost(String urlpost, String username,String password) {

        String postparam = "usuario="+username+"&password="+password;
        InputStream is;
        String result;
        HttpURLConnection conn;

        try {
            String contentAsString = "";
            String tempString;
            URL url = new URL(urlpost);
      
            System.out.println("Abriendo conexión: " + url.getHost()
                    + " puerto=" + url.getPort());
            conn = (HttpURLConnection) url.openConnection();
            conn.setReadTimeout(10000 /* milliseconds */);
            conn.setConnectTimeout(15000 /* milliseconds */);
            conn.setRequestMethod("POST");

            conn.setDoInput(true);
            conn.setDoOutput(true);

            //Send request
            OutputStream os = conn.getOutputStream();

            try (BufferedWriter wr = new BufferedWriter(
                    new OutputStreamWriter(os, "UTF-8"))) {
                wr.write(postparam);
                wr.flush();
            }

            // Starts the query
            conn.connect();
            final int response = conn.getResponseCode();
            final int contentLength = conn.getHeaderFieldInt("Content-length", 1000);

            System.out.println("Cod Respuesta del servidor: "+response);
            is = conn.getInputStream();
         
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));

            while ((tempString = br.readLine()) != null) {
                contentAsString = contentAsString + tempString;
            }
            is.close();
            conn.disconnect();

            return contentAsString;

        } catch (IOException e) {
            result = "Excepción: " + e.getMessage();
            System.out.println(result);
        }

        return result;
    }
        
    
    /**
     * @param args the command line arguments
     * 
     */
    public static void main(String[] args) throws Exception{
        ByteArrayInputStream bais=null;
        
        //TAREA 2. Conseguir que el método LeerNIF de ObtenerDatos devuelva  
        //         correctamente los datos de usuario 
        ObtenerDatos od = new ObtenerDatos();
        Usuario user = od.LeerNIF();
        if(user!=null)
            System.out.println("Usuario: "+user.toString());
        
        //TAREA 3. AUTENTICAR EL CLIENTE CON EL SERVIDOR
        String [] credenciales = user.toString().split(" ");
        String username = credenciales[0].substring(0,1) + credenciales[1] + credenciales[2].substring(0,1);
        String password = credenciales[3];
        
        String respuesta = enviarCredencialesPost("http://localhost/ATTA/Servidor/login.php", username,password);
        
        int inicio = respuesta.indexOf("<h4>");
        int fin = respuesta.indexOf("</h4>");
        
        respuesta = respuesta.substring(inicio+4,fin);
        
        System.out.println("respuesta: " + respuesta);
        
    }
}
