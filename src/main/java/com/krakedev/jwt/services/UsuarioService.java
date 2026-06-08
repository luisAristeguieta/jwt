package com.krakedev.jwt.services;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }
    
    public Usuario guardar(Usuario usuario) {
        if (usuarioRepository.existsByUsername(usuario.getUsername())) {
            throw new RuntimeException("El username '" + usuario.getUsername() + "' se encuentra registrado");
        }
        
     // Encriptar contraseña con BCrypt se agregan: 
        String passwordEncriptada = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());
        usuario.setPassword(passwordEncriptada);
        
        return usuarioRepository.save(usuario);
    }

    // Retorno el usuario para ejercicio y no boolean / Guardando el password visible sin encriptacion: 
    public Usuario autenticar(String username, String password) {
        Usuario usuario = usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + username));

        if (!usuario.getPassword().equals(password)) {
            throw new RuntimeException("Contraseña incorrecta");
        }
        
        return usuario;
    }
}