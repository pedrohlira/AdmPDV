package br.com.phdss;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.Normalizer;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JComboBox;
import javax.swing.text.MaskFormatter;
import javax.xml.bind.DatatypeConverter;
import org.jasypt.util.digest.Digester;
import org.jasypt.util.text.BasicTextEncryptor;

/**
 * Classe responsavel para funcoes utilitarias.
 *
 * @author Pedro H. Lira
 */
public class Util {

    // tabela com vinculos das letras
    private static Properties config;
    private static final int[] pesoCPF = {11, 10, 9, 8, 7, 6, 5, 4, 3, 2};
    private static final int[] pesoCNPJ = {6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
    public static final String[] OPCOES = {"Sim", "Não"};

    /**
     * Constutor padrao.
     */
    private Util() {
    }

    /**
     * Metodo que normaliza os caracteres removendo os acentos.
     *
     * @param texto o texto acentuado.
     * @return o texto sem acentos.
     */
    public static String normaliza(String texto) {
        CharSequence cs = new StringBuilder(texto == null ? "" : texto);
        return Normalizer.normalize(cs, Normalizer.Form.NFKD).replaceAll("\\p{InCombiningDiacriticalMarks}+", "");
    }

    /**
     * Metodo que normaliza os caracteres removendo os acentos de todos os
     * campos de um objeto.
     *
     * @param bloco o objeto que sera modificado.
     */
    public static void normaliza(Object bloco) {
        for (Method metodo : bloco.getClass().getMethods()) {
            try {
                if (isGetter(metodo)) {
                    Object valorMetodo = metodo.invoke(bloco, new Object[]{});

                    if (metodo.getReturnType() == String.class) {
                        String nomeMetodo = metodo.getName().replaceFirst("get", "set");
                        Method set = bloco.getClass().getMethod(nomeMetodo, new Class[]{String.class});
                        String valor = valorMetodo == null ? "" : valorMetodo.toString();
                        valor = normaliza(valor);
                        set.invoke(bloco, new Object[]{valor.trim()});
                    }
                }
            } catch (Exception ex) {
                // pula o item
            }
        }
    }

    /**
     * Metodo que verifica se existe prefixo definido 't.', 't1.' e seguintes.
     *
     * @param campo valor a ser procurado por um prefixo.
     * @return o mesmo valor se tiver prefixo, 't.campo' caso contrario.
     */
    public static String tratarPrefixo(String campo) {
        // valida se o filtro ja tem prefixo
        Matcher mat = Pattern.compile("^t\\d+\\.").matcher(campo);
        return mat.find() ? campo : "t." + campo;
    }

    /**
     * Metodo que informa se o metodo da classe é do tipo GET.
     *
     * @param method usando reflection para descrobrir os metodos.
     * @return verdadeiro se o metodo for GET, falso caso contrario.
     */
    public static boolean isGetter(Method method) {
        if (!method.getName().startsWith("get")) {
            return false;
        }
        if (method.getParameterTypes().length != 0) {
            return false;
        }
        return !void.class.equals(method.getReturnType());
    }

    /**
     * Metodo que informa se o metodo da classe é do tipo SET.
     *
     * @param method usando reflection para descrobrir os metodos.
     * @return verdadeiro se o metodo for SET, falso caso contrario.
     */
    public static boolean isSetter(Method method) {
        if (!method.getName().startsWith("set")) {
            return false;
        }
        if (method.getParameterTypes().length == 0) {
            return false;
        }
        return void.class.equals(method.getReturnType());
    }

    /**
     * Metodo que formata um texto em data no padrao dd/MM/aaaa
     *
     * @param data o texto da data.
     * @return um objeto Date ou null caso nao consiga fazer o parser.
     */
    public static Date getData(String data) {
        return formataData(data, "dd/MM/yyyy");
    }

    /**
     * Metodo que formata uma data em texto no padrao dd/MM/aaaa
     *
     * @param data o objeto Date.
     * @return uma String formatada ou null caso a data nao seja valida.
     */
    public static String getData(Date data) {
        return formataData(data, "dd/MM/yyyy");
    }

    /**
     * Metodo que formata um texto em data no padrao dd/MM/aaaa HH:mm:ss
     *
     * @param data o texto da data.
     * @return um objeto Date ou null caso nao consiga fazer o parser.
     */
    public static Date getDataHora(String data) {
        return formataData(data, "dd/MM/yyyy HH:mm:ss");
    }

    /**
     * Metodo que formata um texto em hora no padrao HH:mm:ss
     *
     * @param hora o texto da data.
     * @return um objeto Date ou null caso nao consiga fazer o parser.
     */
    public static Date getHora(String hora) {
        return formataData(hora, "HH:mm:ss");
    }

    /**
     * Metodo que formata uma hora em texto no padrao HH:mm:ss
     *
     * @param hora o objeto Date.
     * @return uma String formatada ou null caso a data nao seja valida.
     */
    public static String getHora(Date hora) {
        return formataData(hora, "HH:mm:ss");
    }

    /**
     * Metodo que formata uma data em texto no padrao dd/MM/aaaa HH:mm:ss
     *
     * @param data o objeto Date.
     * @return uma String formatada ou null caso a data nao seja valida.
     */
    public static String getDataHora(Date data) {
        return formataData(data, "dd/MM/yyyy HH:mm:ss");
    }

    /**
     * Metodo que formata a data.
     *
     * @param data a data do tipo Date.
     * @param formato o formado desejado.
     * @return a data formatada como solicidato.
     */
    public static String formataData(Date data, String formato) {
        try {
            return new SimpleDateFormat(formato).format(data);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Metodo que formata a data.
     *
     * @param data a data em formato string.
     * @param formato o formado desejado.
     * @return a data como objeto ou null se tiver erro.
     */
    public static Date formataData(String data, String formato) {
        try {
            return new SimpleDateFormat(formato).parse(data);
        } catch (ParseException ex) {
            return null;
        }
    }

    /**
     * Metodo que faz a formatacao de numeros com inteiros e fracoes
     *
     * @param valor o valor a ser formatado
     * @param inteiros o minimo de inteiros, que serao completados com ZEROS se
     * preciso
     * @param decimal o minimo de decimais, que serao completados com ZEROS se
     * preciso
     * @param grupo se sera colocado separador de grupo de milhar
     * @return uma String com o numero formatado
     */
    public static String formataNumero(String valor, int inteiros, int decimal, boolean grupo) {
        return formataNumero(Double.valueOf(valor), inteiros, decimal, grupo);
    }

    /**
     * Metodo que faz a formatacao de numeros com inteiros e fracoes
     *
     * @param valor o valor a ser formatado
     * @param inteiros o minimo de inteiros, que serao completados com ZEROS se
     * preciso
     * @param decimal o minimo de decimais, que serao completados com ZEROS se
     * preciso
     * @param grupo se sera colocado separador de grupo de milhar
     * @return uma String com o numero formatado
     */
    public static String formataNumero(double valor, int inteiros, int decimal, boolean grupo) {
        NumberFormat nf = NumberFormat.getIntegerInstance();
        nf.setMinimumIntegerDigits(inteiros);
        nf.setMinimumFractionDigits(decimal);
        nf.setMaximumFractionDigits(decimal);
        nf.setGroupingUsed(grupo);
        return nf.format(valor);
    }

    /**
     * Metodo que formata o texto usando a mascara passada.
     *
     * @param texto o texto a ser formatado.
     * @param mascara a mascara a ser usada.
     * @return o texto formatado.
     */
    public static String formataTexto(String texto, String mascara) {
        try {
            MaskFormatter mf = new MaskFormatter(mascara);
            mf.setValueContainsLiteralCharacters(false);
            return mf.valueToString(texto);
        } catch (ParseException ex) {
            return texto;
        }
    }

    /**
     * Metodo que formata o texto.
     *
     * @param texto o texto a ser formatado.
     * @param caracter o caracter que sera repetido.
     * @param tamanho o tamanho total do texto de resposta.
     * @param direcao a direcao onde colocar os caracteres.
     * @return o texto formatado.
     */
    public static String formataTexto(String texto, String caracter, int tamanho, EDirecao direcao) {
        StringBuilder sb = new StringBuilder();
        int fim = tamanho - texto.length();
        for (int i = 0; i < fim; i++) {
            sb.append(caracter);
        }

        if (direcao == EDirecao.DIREITA) {
            return texto + sb.toString();
        } else if (direcao == EDirecao.ESQUERDA) {
            return sb.toString() + texto;
        } else {
            return sb.toString().substring(0, fim / 2) + texto + sb.toString().substring(fim / 2);
        }
    }

    /**
     * Metodo que calcula o digito.
     *
     * @param str valor do texto.
     * @param peso array de pesos.
     * @return um numero calculado.
     */
    private static int calcularDigito(String str, int[] peso) {
        int soma = 0;
        for (int indice = str.length() - 1, digito; indice >= 0; indice--) {
            digito = Integer.parseInt(str.substring(indice, indice + 1));
            soma += digito * peso[peso.length - str.length() + indice];
        }
        soma = 11 - soma % 11;
        return soma > 9 ? 0 : soma;
    }

    /**
     * Metodo que valida se e CPF
     *
     * @param cpf o valor do texto.
     * @return verdadeiro se valido, falso caso contrario.
     */
    public static boolean isCPF(String cpf) {
        if ((cpf == null) || (cpf.length() != 11)) {
            return false;
        } else {
            Pattern p = Pattern.compile(cpf.charAt(0) + "{11}");
            Matcher m = p.matcher(cpf);
            if (m.find()) {
                return false;
            }
        }

        Integer digito1 = calcularDigito(cpf.substring(0, 9), pesoCPF);
        Integer digito2 = calcularDigito(cpf.substring(0, 9) + digito1, pesoCPF);
        return cpf.equals(cpf.substring(0, 9) + digito1.toString() + digito2.toString());
    }

    /**
     * Metodo que valida se e CNPJ
     *
     * @param cnpj o valor do texto.
     * @return verdadeiro se valido, falso caso contrario.
     */
    public static boolean isCNPJ(String cnpj) {
        if ((cnpj == null) || (cnpj.length() != 14)) {
            return false;
        } else {
            Pattern p = Pattern.compile(cnpj.charAt(0) + "{14}");
            Matcher m = p.matcher(cnpj);
            if (m.find()) {
                return false;
            }
        }

        Integer digito1 = calcularDigito(cnpj.substring(0, 12), pesoCNPJ);
        Integer digito2 = calcularDigito(cnpj.substring(0, 12) + digito1, pesoCNPJ);
        return cnpj.equals(cnpj.substring(0, 12) + digito1.toString() + digito2.toString());
    }

    /**
     * Metodo que recupera as configuracoes do sistema.
     *
     * @return Um mapa de String contendo chave/valor.
     */
    public static Properties getConfig() {
        if (config == null) {
            config = new Properties();
            try (FileInputStream fis = new FileInputStream("conf" + System.getProperty("file.separator") + "config.properties")) {
                config.load(fis);
            } catch (Exception ex) {
                config = null;
            }
        }
        return config;
    }

    /**
     * Metodo que seleciona um item da combo pelo valor.
     *
     * @param combo a ser verificada.
     * @param valor a ser comparado.
     */
    public static void selecionarCombo(JComboBox combo, String valor) {
        for (int i = 0; i < combo.getItemCount(); i++) {
            String item = combo.getItemAt(i).toString();
            if (item.startsWith(valor)) {
                combo.setSelectedIndex(i);
                break;
            }
        }
    }

    /**
     * Metodo que criptografa o arquivo auxiliar do sistema.
     *
     * @param path local de geracao do arquivo, se null salva no padrao.
     * @param mapa conjunto de dados chave/valor.
     * @throws Exception dispara caso nao consiga.
     */
    public static void criptografar(String path, Properties mapa) throws Exception {
        if (path == null) {
            path = "conf" + System.getProperty("file.separator") + "auxiliar.txt";
        }
        // recuperando os valores
        StringBuilder sb = new StringBuilder();
        for (String chave : mapa.stringPropertyNames()) {
            sb.append(chave).append("=").append(mapa.getProperty(chave)).append("\n");
        }

        if (new File(path).exists()) {
            try (FileWriter outArquivo = new FileWriter(path)) {
                String dados = encriptar(sb.toString());
                outArquivo.write(dados);
                outArquivo.flush();
            }
        } else {
            throw new Exception("Arquivo nao existe -> " + path);
        }
    }

    /**
     * Metodo que descriptografa o arquivo auxiliar do sistema.
     *
     * @param path local de geracao do arquivo, se null recupera do padrao.
     * @param mapa conjunto de dados chave/valor.
     * @throws Exception dispara caso nao consiga.
     */
    public static void descriptografar(String path, Properties mapa) throws Exception {
        if (path == null) {
            path = "conf" + System.getProperty("file.separator") + "auxiliar.txt";
        }
        // lendo dados do arquivo para assinar
        mapa.clear();
        byte[] bytes;
        if (new File(path).exists()) {
            try (FileInputStream inArquivo = new FileInputStream(path)) {
                bytes = new byte[inArquivo.available()];
                inArquivo.read(bytes);
            }
        } else {
            throw new Exception("Arquivo nao existe -> " + path);
        }

        // inserindo os valores
        String[] props = descriptar(new String(bytes)).split("\n");
        for (String prop : props) {
            if (prop.contains("=")) {
                String[] chaveValor = prop.split("=");
                mapa.put(chaveValor[0], chaveValor[1]);
            }
        }
    }

    /**
     * Metodo que criptografa um texto passado usando a chave privada.
     *
     * @param texto valor a ser criptografado.
     * @return o texto informado criptografado.
     */
    public static String encriptar(String texto) {
        if (texto != null) {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(ChavePrivada.VALOR);
            return encryptor.encrypt(texto);
        } else {
            return null;
        }
    }

    /**
     * Metodo que descriptografa um texto passado usando a chave privada.
     *
     * @param texto valor a ser descriptografado.
     * @return o texto informado descriptografado.
     */
    public static String descriptar(String texto) {
        if (texto != null) {
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            encryptor.setPassword(ChavePrivada.VALOR);
            return encryptor.decrypt(texto);
        } else {
            return null;
        }
    }

    /**
     * Metodo que informa o path dos arquivos e caso nao exista ja cria-o.
     *
     * @return uma String com o caminho do path ou null caso nao consiga criar.
     */
    public static String getPathArquivos() {
        StringBuilder path = new StringBuilder(System.getProperty("user.dir"));
        path.append(System.getProperty("file.separator"));
        path.append("arquivos");
        path.append(System.getProperty("file.separator"));

        File f = new File(path.toString());
        if (!f.exists()) {
            f.mkdir();
        }

        return path.toString();
    }

    /**
     * Metodo que adiciona a assinatura ao final do arquivo.
     *
     * @param path path completo do arquivo a ser assinado.
     * @throws Exception dispara caso nao consiga.
     */
    public static void assinarArquivoEAD(String path) throws Exception {
        String ead = gerarEAD(path);
        try (FileWriter outArquivo = new FileWriter(path, true)) {
            outArquivo.write(ead);
            outArquivo.write("\r\n");
            outArquivo.flush();
        }
    }

    /**
     * Metodo que gera uma assinatura usando a chave privada com os dados de
     * todos os campos do registro.
     *
     * @param dado o objeto contendo os dados.
     * @return a String com a assinatura deste registro.
     * @throws Exception dispara caso nao consiga.
     */
    public static String gerarEAD(Object dado) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (Field campo : dado.getClass().getDeclaredFields()) {
            campo.setAccessible(true);
            boolean isTransient = Modifier.isTransient(campo.getModifiers());
            if (!campo.getName().toLowerCase().equals("ead") && !campo.getName().toLowerCase().endsWith("id") && !isTransient) {
                try {
                    if (campo.getType() == int.class) {
                        sb.append(campo.getInt(dado));
                    } else if(campo.getType() == long.class) {
                        sb.append(campo.getLong(dado));
                    } else if (campo.getType() == boolean.class) {
                        sb.append(campo.getBoolean(dado));
                    } else if(campo.getType() == float.class) {
                        sb.append(campo.getFloat(dado));
                    } else if (campo.getType() == double.class) {
                        sb.append(campo.getDouble(dado));
                    } else if (campo.getType() == char.class) {
                        sb.append(campo.getChar(dado));
                    } else if(campo.getType() == Date.class){
                        Date data = (Date) campo.get(dado);
                        sb.append(Util.getDataHora(data));
                    } else if (campo.getType() == Integer.class || campo.getType() == Long.class || campo.getType() == String.class || campo.getType() == Boolean.class || campo.getType() == Float.class || campo.getType() == Double.class || campo.getType() == Character.class) {
                        sb.append(campo.get(dado).toString());
                    }
                } catch (Exception ex) {
                    // nada
                }
            }
        }
        return gerarEAD(sb.toString().toLowerCase().getBytes());
    }

    /**
     * Metodo que retorna a assinatura do arquivo.
     *
     * @param path path completo do arquivo a gerado a assinatura.
     * @return retorna a assinatura em EAD.
     * @throws Exception dispara caso nao consiga.
     */
    public static String gerarEAD(String path) throws Exception {
        // lendo dados do arquivo para assinar
        byte[] dados;
        if (new File(path).exists()) {
            try (FileInputStream inArquivo = new FileInputStream(path)) {
                dados = new byte[inArquivo.available()];
                inArquivo.read(dados);
            }
        } else {
            throw new Exception("Arquivo nao existe -> " + path);
        }
        // retornando a assinatura.
        return gerarEAD(dados);
    }

    /**
     * Metodo que retorna a assinatura do array de bytes.
     *
     * @param dados os bytes para ser gerado a assinatura.
     * @return retorna a assinatura em EAD.
     * @throws Exception dispara caso nao consiga.
     */
    public static String gerarEAD(byte[] dados) throws Exception {
        // configurando a chave
        byte[] privateKeyBytes = DatatypeConverter.parseBase64Binary(ChavePrivada.VALOR);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // recuperando assinatura do arquivo
        Signature sig = Signature.getInstance("MD5withRSA");
        sig.initSign(privateKey);
        sig.update(dados);

        // retornando a assinatura.
        return "EAD" + new BigInteger(1, sig.sign()).toString(16);
    }

    /**
     * Metodo que gera o MD5 de um arquivo informado.
     *
     * @param path o path completo do arquivo.
     * @return o codigo MD5 do arquivo.
     * @throws Exception dispara caso nao consiga.
     */
    public static String gerarMD5(String path) throws Exception {
        // lendo dados do arquivo para assinar
        byte[] dados;
        if (new File(path).exists()) {
            try (FileInputStream inArquivo = new FileInputStream(path)) {
                dados = new byte[inArquivo.available()];
                inArquivo.read(dados);
            }
        } else {
            throw new Exception("Arquivo nao existe -> " + path);
        }
        return gerarMD5(dados);
    }

    /**
     * Metodo que gera o MD5 de um array de bytes informado.
     *
     * @param dados os bytes dos dados a serem usados.
     * @return o codigo MD5 do arquivo.
     * @throws Exception dispara caso nao consiga.
     */
    public static String gerarMD5(byte[] dados) throws Exception {
        // gerando o MD5
        Digester md5 = new Digester("MD5");
        return new BigInteger(1, md5.digest(dados)).toString(16);
    }

    /**
     * Enum que define qual a opcao usadada na formatacao do texto.
     */
    public static enum EDirecao {

        /**
         * Coloca o caracter nos dois lados do texto.
         */
        AMBOS,
        /**
         * Coloca o caracter no lado direto do texo.
         */
        DIREITA,
        /**
         * Coloca o caracter no lado esquerdo do texto.
         */
        ESQUERDA
    };
}
