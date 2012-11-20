package br.com.phdss;

import java.io.*;
import java.util.Properties;
import org.jasypt.util.password.ConfigurablePasswordEncryptor;
import org.jasypt.util.text.BasicTextEncryptor;

/**
 * Classe que contem a chave privada e criptograva o arquivo auxiliar ou gera
 * uma senha usando a chave privada ou gera o cacerts de todos os estados.
 *
 * @author Pedro H. Lira
 */
public class AdmPDV {

    /**
     * Chave de 1024 bits RSA em base64.
     */
    private static final String VALOR = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKoKq4/wwLUaboZ0FJWcHw70RrPpgXxYa87Zn6hx0ddZVkah/7GZLK11IyfTv2SPPu5yBoL2zSgLcZmQTbaRE8FIV/xp6FVOKl6vKVLJToTRL6sAK+y4tn3v77SMhO3jcAF+UEfkuYA0NhDuP6BSX8xeKsf0QtKXfOUPZKVRWDRJAgMBAAECgYBqmfHgdXB6mS19QTy+ZnfaKi5BEDzLNauwrCI5udFyDmHWOi1Qq9SkkfEOQOOWKW+skPOgGxWW60W2ng76S41z8zgE60hPpHbG377L97+gHx2W2pQqpKqT+HY3nKKKg5LXaOXcJpKg+qWxHuB5HIg1++v69yIphwy3H9ezEMom+QJBANWXzXvegBvAgPP1CSjQqOohljJu1DQvNkycDR08igt6u1hrKE+5TnqtH/oTct2HMr3Dytt8WUwZhIMzRfRkpQMCQQDLzU356B5EbjT43drzk3sVUIO8gqFnZd27dr7h2rhez09Fhvs9uhNCrxAau0MyHjuQqdcIK1jMo5p9q3292IHDAkEAtat+LQNctz4O8HDUL5D6etnCZHb7qr8VUifQx7M8PvNO8a+DA/w7EgC6l/t+0Yky0VD8855aXW2+1dEAiRQpfQJADeQhg34pyfpFDA17Jg0QX6SMRiYVQEn2Mhfm7NgOpw+0VIXdzBhJxcrO6zOGYf0jjDm3WWwy8kfYeOZefLksJwJBANO/nX1TLdcumFQnV0C4zfBWU6daCYYPO7zhYS83SCr66uyT7agJOAB91jEDPxUjrpynj5IpW2kh7vNy1zpA/zc=";

    /**
     * Construtor padrao.
     */
    private AdmPDV() {
    }

    /**
     * Metodo de acao externa usado para criptografar o arquivo auxiliar, senha
     * e gerar cacerts.
     *
     * [opcao] = arquivo, para criptogravar o arquivo auxiliar.properties.
     * [opcao] = senha, para criptogravar uma senha informada. [opcao] =
     * cacerts, para gerar o arquivo NFeCacerts de todos os estados.
     *
     * @param args um array sendo o primeiro parametro uma das opcoes acima.
     */
    public static void main(String[] args) {
        if (args.length == 1) {
            Console console = System.console();
            if (console == null) {
                System.out.println("Erro ao recuperar o console.");
                System.exit(0);
            } else {
                char pws[] = console.readPassword("Informe a senha do ADM: ");
                if (!validarSenha(new String(pws))) {
                    System.out.println("Senha de ADM informada incorreta.");
                    System.exit(0);
                }
            }

            if (args[0].equalsIgnoreCase("arquivo")) {
                String path = console.readLine("Informe o path do arquivo:");
                File arquivo = new File(path);

                try (FileInputStream fis = new FileInputStream(arquivo)) {
                    // recuperando os valores
                    StringBuilder sb = new StringBuilder();

                    if (arquivo.getName().endsWith(".properties")) {
                        Properties prop = new Properties();
                        prop.load(fis);
                        for (String chave : prop.stringPropertyNames()) {
                            sb.append(chave).append("=").append(prop.getProperty(chave)).append("\n");
                        }
                    } else {
                        try (BufferedReader br = new BufferedReader(new FileReader(arquivo))) {
                            while (br.ready()) {
                                sb.append(br.readLine()).append("\n");
                            }
                        }
                    }

                    // salva o arquivo
                    try (FileWriter outArquivo = new FileWriter(arquivo.getAbsolutePath().replace("properties", "txt"))) {
                        BasicTextEncryptor encryptor = new BasicTextEncryptor();
                        encryptor.setPassword(VALOR);
                        String dados = encryptor.encrypt(sb.toString());

                        outArquivo.write(dados);
                        outArquivo.flush();
                    }

                    System.out.println("Arquivo criptografado: " + arquivo.getAbsolutePath().replace("properties", "txt"));
                } catch (Exception ex) {
                    System.out.println("Nao foi possivel ler ou gerar o arquivo criptografado.");
                    ex.printStackTrace(System.out);
                }
                System.exit(0);
            } else if (args[0].equalsIgnoreCase("senha")) {
                char pws[] = console.readPassword("Informe a senha para criptografar: ");
                BasicTextEncryptor seguranca = new BasicTextEncryptor();
                seguranca.setPassword(VALOR);
                String senha = seguranca.encrypt(new String(pws));
                System.out.println("Senha criptografada: " + senha);
                System.exit(0);
            } else if (args[0].equalsIgnoreCase("cacerts")) {
                Cacerts.gerar();
                System.exit(0);
            }
        }

        System.out.println("Falta a informar a [opcao] de utilizacao.");
        System.out.println("\t[opcao] = arquivo, para criptogravar o arquivo auxiliar.properties.");
        System.out.println("\t[opcao] = senha, para criptogravar uma senha informada.");
        System.out.println("\t[opcao] = cacerts, para gerar o arquivo NFeCacerts de todos os estados.");
    }

    /**
     * Metodo que compara a senha informada com a senha de ADM salva.
     *
     * @param senha a senha digitada no console.
     *
     * @return true se for igual , false se nao for igual.
     */
    private static boolean validarSenha(String senha) {
        ConfigurablePasswordEncryptor sha = new ConfigurablePasswordEncryptor();
        sha.setAlgorithm("SHA-1");
        sha.setPlainDigest(true);
        sha.setStringOutputType("hexadecimal");
        senha = sha.encryptPassword(senha);
        return senha.equals("852A0B1988AE0DF88DA242C7277360FBF5639A8E");
    }
}
