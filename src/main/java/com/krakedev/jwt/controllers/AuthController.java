package com.krakedev.jwt.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JwtUtil;

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
			// Generar token JWT
			String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());
			return ResponseEntity
					.ok(Map.of("token", token, "username", usuario.getUsername(), "rol", usuario.getRol()));
		} catch (RuntimeException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
		}
	}

	@GetMapping("/perfil")
	public ResponseEntity<?> verPerfil(@RequestHeader(value = "Authorization", required = false) String authHeader) {

		// Validar que el header Authorization se encuentre
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body("Acceso Denegado: Debes proveer un token Bearer válido en la cabecera Authorization");
		}

		// Extraer el token (quitar "Bearer ")
		String token = authHeader.substring(7);

		// Validar el token
		DecodedJWT datosToken = JwtUtil.validarToken(token);

		if (datosToken == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Acceso Denegado: Token Inválido o Expirado");
		}

		// Extraer información del token
		String usuario = datosToken.getSubject();
		String rol = datosToken.getClaim("rol").asString();

		// Mensaje personalizado para el rol
		String mensaje;
		if ("ADMIN".equals(rol)) {
			mensaje = "Bienvenido Voluntario del Refugio " + usuario + "! Puedes gestionar rescates y fichas de salud.";
		} else {
			mensaje = "Bienvenido Adoptante " + usuario + "! Puedes ver mascotas disponibles y actualizar tus datos.";
		}

		return ResponseEntity
				.ok(Map.of("mensaje", mensaje, "usuario", usuario, "rol", rol, "estatus", "Autenticado exitosamente"));
	}
}