create database IF NOT EXISTS bancotb;
use bancotb;
-- drop database bancotb;
create table IF NOT EXISTS usuario(
idusuario int primary key auto_increment not null,
nome varchar(70) not null,
email varchar(70) not null,
senha varchar(70) not null,
profileImage VARCHAR(255),
resetPasswordToken VARCHAR(255),
resetPasswordExpires DATETIME
);
select * from usuario;
-- select * from usuario where email = 'acerolo'AND senha = '235235';
-- truncate table usuario;

-- delete from usuario where idusuario = '1';

CREATE TABLE IF NOT EXISTS progresso_usuario (
    id INT AUTO_INCREMENT PRIMARY KEY, -- Identificador único para cada registro
    usuarioId INT NOT NULL,            -- Relacionado à tabela de usuários
    cursoId INT NOT NULL,              -- Identificador do curso
    videosAssistidos INT DEFAULT 0,    -- Quantidade de vídeos assistidos
    progresso DECIMAL(5, 2) DEFAULT 0, -- Porcentagem de progresso
    FOREIGN KEY (usuarioId) REFERENCES usuario(idusuario) -- Chave estrangeira para a tabela de usuários
);
select * from progresso_usuario;
-- drop table progresso_usuario;
-- delete from progresso_usuario where usuarioId = '1';
-- truncate table progresso_usuario;

CREATE TABLE IF NOT EXISTS videos_assistidos (
    id INT AUTO_INCREMENT PRIMARY KEY, -- Identificador único para cada registro
    usuarioId INT NOT NULL,            -- Relacionado à tabela de usuários
    cursoId INT NOT NULL,              -- Relacionado ao id do curso
    videoId VARCHAR(255) NOT NULL,              -- Identificador do vídeo assistido
    dataAssistido TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Data em que o vídeo foi assistido
    FOREIGN KEY (usuarioId) REFERENCES usuario(idusuario), -- Relacionado à tabela de usuários
    INDEX idx_videoId (videoId)
);
-- ALTER TABLE videos_assistidos MODIFY COLUMN videoId VARCHAR(255);
-- truncate table videos_assistidos;

CREATE TABLE IF NOT EXISTS favorites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    curso_id VARCHAR(255),
    FOREIGN KEY (usuario_id) REFERENCES usuario(idusuario),
    UNIQUE(usuario_id, curso_id) -- Evita duplicatas
);
select * from favorites;

CREATE TABLE IF NOT EXISTS avaliacoes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuarioId INT NOT NULL,
    cursoId INT NOT NULL,
    videoId VARCHAR(255) NOT NULL,
    avaliacao INT NOT NULL CHECK (avaliacao >= 1 AND avaliacao <= 5),
    data_avaliacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuarioId) REFERENCES usuario(idusuario),
    FOREIGN KEY (videoId) REFERENCES videos_assistidos(videoId),
    CONSTRAINT unique_user_course_video UNIQUE (usuarioId, cursoId, videoId)
);
-- drop table avaliacoes;
-- truncate table avaliacoes;
select usuarioId, cursoId, videoId, avaliacao from avaliacoes;