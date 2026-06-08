package com.krakedev.jwt.controllers;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final UsuarioService usuarioService;

	public AuthController(UsuarioService usuarioService) {
		this.usuarioService = usuarioService;
	}

	@PostMapping("/registrar")
	public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {
		try {
			Usuario nuevo = usuarioService.guardar(usuario);
			return ResponseEntity.status(HttpStatus.CREATED).body(nuevo); // Mostrara password encriptado
		} catch (RuntimeException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al registrar usuario");
		}
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {
		String username = credenciales.get("username");
		String password = credenciales.get("password");

		try {
			Usuario usuario = usuarioService.autenticar(username, password);
			return ResponseEntity
					.ok(Map.of("mensaje", "Login exitoso", "username", usuario.getUsername(), "rol", usuario.getRol()));
		} catch (RuntimeException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
		}
	}
}