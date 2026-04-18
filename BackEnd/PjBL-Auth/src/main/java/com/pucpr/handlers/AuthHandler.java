package com.pucpr.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    public void handleLogin(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            // 1. Lê e converte o corpo da requisição
            byte[] bytes = exchange.getRequestBody().readAllBytes();
            Map<String, Object> body = mapper.readValue(bytes, Map.class);

            String email = (String) body.get("email");
            String senha = (String) body.get("password");

            // 2. Busca o usuário pelo e-mail
            Optional<Usuario> usuarioOpt = repository.findByEmail(email);

            // 3. Valida existência e senha com BCrypt
            if (usuarioOpt.isEmpty() || !BCrypt.checkpw(senha, usuarioOpt.get().getSenhaHash())) {
                // Mensagem GENÉRICA — não revela se foi o e-mail ou a senha
                sendResponse(exchange, 401, "{\"erro\": \"E-mail ou senha inválidos.\"}");
                return;
            }

            // 4. Gera o token e responde
            String token = jwtService.generateToken(usuarioOpt.get());
            String resposta = "{\"token\": \"" + token + "\"}";
            sendResponse(exchange, 200, resposta);

        } catch (Exception e) {
            sendResponse(exchange, 500, "{\"erro\": \"Erro interno no servidor.\"}");
        }
    }

    public void handleRegister(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);

        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            // 1. Lê e converte o corpo da requisição
            byte[] bytes = exchange.getRequestBody().readAllBytes();
            Map<String, Object> body = mapper.readValue(bytes, Map.class);

            String nome  = (String) body.get("name");
            String email = (String) body.get("email");
            String senha = (String) body.get("password");
            String role  = (String) body.getOrDefault("role", "PACIENTE");

            // 2. Verifica se e-mail já existe
            if (repository.findByEmail(email).isPresent()) {
                sendResponse(exchange, 400, "{\"erro\": \"E-mail já cadastrado.\"}");
                return;
            }

            // 3. Gera o hash da senha com BCrypt (fator 12)
            String senhaHash = BCrypt.hashpw(senha, BCrypt.gensalt(12));

            // 4. Cria e salva o usuário
            Usuario novoUsuario = new Usuario(nome, email, senhaHash, role);
            repository.save(novoUsuario);

            sendResponse(exchange, 201, "{\"mensagem\": \"Usuário cadastrado com sucesso.\"}");

        } catch (Exception e) {
            sendResponse(exchange, 500, "{\"erro\": \"Erro interno no servidor.\"}");
        }
    }

    // --- Métodos auxiliares ---

    private void sendResponse(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }
}