import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.*;

/**
 * La clase ObtenerDatos implementa cuatro métodos públicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 * 
 *
 * @author tbc
 */
public class ObtenerDatos {

    private static final byte[] dnie_v_1_0_Atr = {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
        (byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00};
    private static final byte[] dnie_v_1_0_Mask = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

    public ObtenerDatos() {
    }

    public Usuario LeerNIF() {

        Usuario user = null;
        byte[] datos=null;
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("ACCESO DNIe: No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                datos = leerCertificado(ch);
                //System.out.println(datos);
                if(datos!=null)
                    user = leerDatosUsuario(datos);
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return user;
    }

    public byte[] leerCertificado(CardChannel ch) throws CardException, CertificateException {


        int offset = 0;
        String completName = null;

        //[1] PRÁCTICA 3. Punto 1.a
        /*
        El comando que se usa aquí es el comando "Select" con los siguientes valores para cada campo.
        CLA--> 0x00
        INS--> 0xA4
        P1--> 0x04 seleccion directa de DF por nombre
        P2--> 0x00
        LC--> 0x0b Longitud del campo de datos
        Data--> 
        LE--> vacío
        */
        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[2] PRÁCTICA 3. Punto 1.a
        /*
        El comando que se usa aquí es el comando "Select" con los siguientes valores para cada campo.
        CLA--> 0x00
        INS--> 0xA4
        P1--> 0x00 Selecciona DF o EF por Id (data field = id)
        P2--> 0x00
        LC--> 0x02 Longitud del campo de datos 
        Creo que los dos últimos valores hacen referencia al ID del fichero elemental que se esta seleccionando
        para ello el comando tiene que tener el valor de P1=0x00 para seleccionar por ID. 
        */       
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[3] PRÁCTICA 3. Punto 1.a
        /*
        El comando que se usa aquí es el comando "Select" con los siguientes valores para cada campo.
        CLA--> 0x00
        INS--> 0xA4
        P1--> 0x00 Selecciona DF o EF por Id (data field = id)
        P2--> 0x00
        LC--> 0x02 Longitud del campo de datos
        Creo que los dos últimos valores hacen referencia al ID del fichero elemental que se esta seleccionando
        para ello el comando tiene que tener el valor de P1=0x00 para seleccionar por ID.
        */       
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
        r = ch.transmit(new CommandAPDU(command));

        byte[] responseData = null;
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        } else {
            responseData = r.getData();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] r2 = null;
        int bloque = 0;

        do {
             //[4] PRÁCTICA 3. Punto 1.b
             /*
             Los valores de CLA INS y LE que se ven aqui son parte del comando "Read Binary".
             El comando "Read Binary" devuelve en su mensaje de respuesta el contenido (o parte) de un fichero elemental transparente.
             LE es el número de bytes a leer, si LE=0 el numero de bytes a leer es de 256.
             */
            final byte CLA = (byte) 0x00;//Buscar qué valor poner aquí (0xFF no es el correcto)
            final byte INS = (byte) 0xB0;//Buscar qué valor poner aquí (0xFF no es el correcto)
            final byte LE = (byte) 0xFF;// Identificar qué significa este valor

            //[5] PRÁCTICA 3. Punto 1.b
            /*
            P1 y P2 lo que hacen es decir hasta donde se lee el fichero en la primera lectura y a partir 
            de esta nos dice a partir de donde debemos empezar a leer y hasta donde tenemos que llegar en
            esa lectura.
            */
            command = new byte[]{CLA, INS, (byte) bloque/*P1*/, (byte) 0x00/*P2*/, LE};//Identificar qué hacen P1 y P2
            r = ch.transmit(new CommandAPDU(command));

            //System.out.println("ACCESO DNIe: Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));

            if ((byte) r.getSW() == (byte) 0x9000) {
                r2 = r.getData();

                baos.write(r2, 0, r2.length);

                for (int i = 0; i < r2.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = r2[i];
                    System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + String.format(" %d", r2[i])+" "+new String(t));
                }
                bloque++;
            } else {
                return null;
            }

        } while (r2.length >= 0xfe);


         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

      

        
        return baos.toByteArray();
    }

    
    
    
    /**
     * Este método establece la conexión con la tarjeta. La función busca el
     * Terminal que contenga una tarjeta, independientemente del tipo de tarjeta
     * que sea.
     *
     * @return objeto Card con conexión establecida
     * @throws Exception
     */
    private Card ConexionTarjeta() throws Exception {

        Card card = null;
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        //System.out.println("Terminals: " + terminals);

        for (int i = 0; i < terminals.size(); i++) {

            // get terminal
            CardTerminal terminal = terminals.get(i);

            try {
                if (terminal.isCardPresent()) {
                    card = terminal.connect("*"); //T=0, T=1 or T=CL(not needed)
                }
            } catch (Exception e) {

                System.out.println("Exception catched: " + e.getMessage());
                card = null;
            }
        }
        return card;
    }

    /**
     * Este método nos permite saber el tipo de tarjeta que estamos leyendo del
     * Terminal, a partir del ATR de ésta.
     *
     * @param atrCard ATR de la tarjeta que estamos leyendo
     * @return tipo de la tarjeta. 1 si es DNIe, 2 si es Starcos y 0 para los
     * demás tipos
     */
    private boolean esDNIe(byte[] atrCard) {
        int j = 0;
        boolean found = false;

        //Es una tarjeta DNIe?
        if (atrCard.length == dnie_v_1_0_Atr.length) {
            found = true;
            while (j < dnie_v_1_0_Atr.length && found) {
                if ((atrCard[j] & dnie_v_1_0_Mask[j]) != (dnie_v_1_0_Atr[j] & dnie_v_1_0_Mask[j])) {
                    found = false; //No es una tarjeta DNIe
                }
                j++;
            }
        }

        if (found == true) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Analizar los datos leídos del DNIe para obtener
     *   - nombre
     *   - apellidos
     *   - NIF
     * @param datos
     * @return 
     */
    private Usuario leerDatosUsuario(byte[] datos) {
        int offset=0;
        //String completName=null;
        String nif=null;
        String apellido1= null;
        String apellido2= null;
        String nombre = null;
        
        //Buscamos el oid que hay justo antes de donde se muestra el nif en la hoja de excel.
        //Una vez encontrado este oid lo que hacemos es aplicarle un offset hasta llegar a
        //donde empieza el nif.

            if (datos[4] == 0x30) {
                offset = 4;
                offset += datos[offset + 1] + 2; //Obviamos la seccion del Label
            }

            if (datos[offset] == 0x30) {
                offset += datos[offset + 1] + 2; //Obviamos la seccion de la informacion sobre la fecha de expedición etc
            }

            if ((byte) datos[offset] == (byte) 0xA1) {
                //El certificado empieza aquí
                byte[] r3 = new byte[9];
                byte[] r4 = new byte[6];
                byte[] r5 = new byte[7];
                byte[] r6 = new byte[4];
                
        
                //Nos posicionamos en el byte donde empieza el NIF y leemos sus 9 bytes
                for (int z = 0; z < 9; z++) {
                    r3[z] = datos[109 + z];
                }
                nif = new String(r3);
                
                //Nos posicionamos en el byte donde empiezan los apellido1 y leemos sus 6 bytes.
                for(int v=0; v<6; v++){
                    r4[v] = datos[161+v];
                }
                apellido1= new String(r4);
                
                //Nos posicionamos en el byte donde empiezan los apellido2 y leemos sus 7 bytes.
                for(int w=0; w<7; w++){
                    r5[w] = datos[168+w];
                }
                apellido2= new String(r5);                
                
                //Nos posicionamos en el byte donde empieza el nombre y leemos sus 4 bytes.
                for(int b=0; b<4; b++){
                    r6[b] = datos[177+b];
                }
                nombre= new String(r6);
            }
            Usuario completName = new Usuario(nombre,apellido1,apellido2,nif);
       return completName;
    }
}
