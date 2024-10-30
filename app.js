const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const path = require('path');
const mime = require('mime-types');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs'); 

const app = express();
const port = process.env.PORT || 3300;

// Verifica se o diretório 'uploads' existe e, se não existir, cria.
const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configuração do body-parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configuração do banco de dados
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Substitua pelo seu usuário do MySQL
    password: 'rodrigo', // Substitua pela sua senha do MySQL
    database: 'bancotb', // Nome do seu banco de dados
});

db.connect((err) => { 
    if (err) {
        throw err;
    }
    console.log('Conectado ao banco de dados MySQL com Sucesso!');
});
app.use(session({
    secret: 'segredo',
    resave: false,    // Certifique-se de que está configurado corretamente
    saveUninitialized: true, // Mantém a sessão, mesmo sem modificações
    cookie: { secure: false } // Deve estar como "false" se você estiver testando em HTTP (não HTTPS)
}));

// Defina o diretório onde as imagens serão salvas
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname)); // gera um nome único
    }
  });
  
  const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Somente imagens são permitidas!'));
        }
    }
    });

  // Rota para o upload de imagem
  app.post('/upload', upload.single('profileImage'), (req, res) => {
    // Verifique se o usuário está logado
    if (!req.session.usuario) {
        return res.status(401).json({ success: false, message: 'Você precisa estar logado para fazer upload de imagens.' });
    }

    if (!req.file) {
        return res.status(400).json({ success: false, message: 'Nenhuma imagem foi enviada.' });
    }

    const imageUrl = `/uploads/${req.file.filename}`;
    const userId = req.session.usuario.idusuario; // Certifique-se de que o ID do usuário está na sessão

    // Atualiza o caminho da imagem no banco de dados para o usuário logado
    const queryUpdateImage = 'UPDATE usuario SET profileImage = ? WHERE idusuario = ?';
    db.query(queryUpdateImage, [imageUrl, userId], (err, result) => {
        if (err) {
            console.error('Erro ao salvar a imagem no banco de dados:', err);
            return res.status(500).json({ success: false, message: 'Erro ao salvar a imagem no banco de dados.' });
        }

        // Enviar uma resposta de sucesso com a URL da imagem
        res.json({ success: true, imageUrl: imageUrl, message: 'Imagem enviada com sucesso.' });
    });
});

app.get('/user/profile', (req, res) => {
    // Verifique se o usuário está logado
    if (!req.session.usuario) {
        return res.status(401).json({ success: false, message: 'Você precisa estar logado.' });
    }

    const userId = req.session.usuario.idusuario;

    // Consulta o banco de dados para obter o nome e a imagem de perfil
    const queryGetUser = 'SELECT nome, profileImage FROM usuario WHERE idusuario = ?';

    db.query(queryGetUser, [userId], (err, result) => {
        if (err) {
            console.error('Erro ao buscar o usuário no banco de dados:', err);
            return res.status(500).json({ success: false, message: 'Erro ao buscar o usuário.' });
        }

        if (result.length > 0) {
            const userData = result[0];
            const userName = userData.nome;
            const userImage = userData.profileImage || '/uploads/default-profile.png'; // Se não houver imagem, usa uma padrão

            return res.json({
                success: true,
                nome: userName,
                profileImage: userImage
            });
        } else {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
        }
    });
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'ttecnobrasa@gmail.com', // seu e-mail
      pass: 'j o x d p b g b e i g j f p l g'            // sua senha ou token de acesso
    }
  });

  // Rota para emitir o certificado e enviar o email de notificação
  app.post('/user/certificado', (req, res) => {
    const { usuarioId, cursoId, nomeCompleto, userEmail } = req.body;

    // Mapeamento dos IDs dos cursos para os nomes correspondentes
    const cursos = {
        1: 'Word',
        2: 'Excel',
        3: 'PowerPoint',
        4: 'Montagem e Manutenção de Computadores',
        5: 'Git'
    };

    // Obter o nome do curso usando o ID do curso
    const nomeCurso = cursos[cursoId] || 'Curso desconhecido';

    const mailOptions = {
        from: 'ttecnobrasa@gmail.com', // Email do remetente
        to: userEmail, // Email do destinatário (do usuário)
        subject: 'Certificado Emitido com Sucesso',
        text: `Olá, ${nomeCompleto}!\n\nParabéns por concluir o curso "${nomeCurso}". Seu certificado foi emitido com sucesso e estará disponível em breve para download.\n\nAtenciosamente,\nEquipe TecnoBrasa`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Erro ao enviar email:', error);
            return res.status(500).json({ success: false, message: 'Erro ao enviar o email de certificado' });
        } else {
            console.log('Email enviado:', info.response);
            return res.status(200).json({ success: true, message: 'Certificado emitido e email enviado com sucesso' });
        }
    });
});

 // Rota para enviar o token de redefinição de senha
app.post('/send-password-reset', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send('E-mail é necessário');
    }

    // Verificar se o email está cadastrado
    const queryVerificar = 'SELECT * FROM usuario WHERE email = ?';
    db.query(queryVerificar, [email], (err, results) => {
        if (err) {
            throw err;
        }
        if (results.length === 0) {
            return res.status(404).send('E-mail não encontrado.');
        }

        // Gerar um token aleatório
        const token = crypto.randomBytes(20).toString('hex');
        const expiracao = new Date(Date.now() + 3600000); // Token válido por 1 hora
        console.log('Token enviado:', token);
        console.log('Token armazenado:', results[0].resetPasswordToken);

        // Inserir o token no banco de dados
        const queryInsert = 'UPDATE usuario SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE email = ?';
        db.query(queryInsert, [token, expiracao, email], (err, result) => {
            if (err) {
                console.error('Erro ao atualizar o token de redefinição de senha:', err);
                return res.status(500).json({ message: 'Erro ao processar o pedido de redefinição de senha.' });
            }

            // Configuração do e-mail
            const mailOptions = {
                from: 'ttecnobrasa@gmail.com',
                to: email,
                subject: 'Redefinição de senha',
                text: `Você solicitou uma redefinição de senha. Use o token abaixo para redefinir sua senha:\n\nToken: ${token}\n\nO token é válido por 1 hora.`
            };

            // Enviar o e-mail
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Erro ao enviar o e-mail:', error);
                    return res.status(500).send('Erro ao enviar o e-mail');
                }
                console.log('E-mail enviado:', info.response);
                res.status(200).send('E-mail de redefinição enviado com sucesso');
            });
        });
    });
});

// Rota para verificar o token
app.post('/verify-token', (req, res) => {
    const { email, token } = req.body;

    const query = 'SELECT * FROM usuario WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > ?';
    db.query(query, [email, token, Date.now()], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Erro no servidor' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Token inválido ou expirado.' });
        }

        res.status(200).json({ success: true, message: 'Token verificado com sucesso. Redefina sua senha.' });
    });
});
// Rota para redefinir a senha com criptografia
app.post('/reset-password', (req, res) => {
    const { email, novaSenha } = req.body;

    // Log para ver o que está sendo recebido
    console.log('E-mail recebido:', email);
    console.log('Nova senha recebida:', novaSenha);

    if (!email || !novaSenha) {
        return res.status(400).json({ message: 'E-mail e nova senha são necessários.' });
    }

    // Gerar um hash da nova senha
    bcrypt.hash(novaSenha, 10, (err, hash) => {
        if (err) {
            console.error('Erro ao criptografar a senha:', err);
            return res.status(500).json({ message: 'Erro ao criptografar a senha.' });
        }

        // Atualizar a senha no banco de dados
        const queryUpdate = 'UPDATE usuario SET senha = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE email = ?';
        db.query(queryUpdate, [hash, email], (err, result) => {
            if (err) {
                console.error('Erro ao atualizar a senha no banco de dados:', err);
                return res.status(500).json({ message: 'Erro ao redefinir a senha.' });
            }

            // Logar o resultado da query para depuração
            console.log('Resultado da query:', result);

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Usuário não encontrado.' });
            }

            res.json({ success: true, message: 'Senha redefinida com sucesso!' });
        });
    });
});

app.post('/change-password', (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.session.usuario.idusuario; // Supondo que o ID do usuário esteja na sessão
  
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Usuário não autenticado.' });
    }
  
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Preencha todos os campos.' });
    }
  
    // Consulta ao banco de dados para pegar a senha atual do usuário
    const query = 'SELECT senha FROM usuario WHERE idusuario = ?';
    db.query(query, [userId], async (err, results) => {
      if (err) {
        console.error('Erro ao consultar o banco de dados:', err);
        return res.status(500).json({ success: false, message: 'Erro ao buscar a senha do usuário.' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
      }
  
      const storedPasswordHash = results[0].senha;
  
      // Verificar se a senha atual está correta
      const passwordMatch = await bcrypt.compare(currentPassword, storedPasswordHash);
      if (!passwordMatch) {
        return res.status(401).json({ success: false, message: 'Senha anterior incorreta.' });
      }
  
      // Verificar se a nova senha é igual à senha atual
      if (await bcrypt.compare(newPassword, storedPasswordHash)) {
        return res.status(400).json({ success: false, message: 'A nova senha não pode ser igual à senha anterior.' });
      }
  
      // Criptografar a nova senha
      const saltRounds = 10;
      const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
  
      // Atualizar a nova senha no banco de dados
      const updateQuery = 'UPDATE usuario SET senha = ? WHERE idusuario = ?';
      db.query(updateQuery, [newPasswordHash, userId], (err, result) => {
        if (err) {
          console.error('Erro ao atualizar a senha no banco de dados:', err);
          return res.status(500).json({ success: false, message: 'Erro ao atualizar a senha.' });
        }
  
        res.json({ success: true, message: 'Senha alterada com sucesso.' });
      });
    });
  });

  app.post('/change-email', (req, res) => {
    const { newEmail, currentPassword } = req.body;
    const userId = req.session.usuario.idusuario; // Supondo que o ID do usuário esteja na sessão

    if (!userId) {
      return res.status(401).json({ success: false, message: 'Usuário não autenticado.' });
    }

    if (!newEmail || !currentPassword) {
      return res.status(400).json({ success: false, message: 'Preencha todos os campos.' });
    }

    // Consulta ao banco de dados para pegar a senha atual do usuário
    const query = 'SELECT senha FROM usuario WHERE idusuario = ?';
    db.query(query, [userId], async (err, results) => {
      if (err) {
        console.error('Erro ao consultar o banco de dados:', err);
        return res.status(500).json({ success: false, message: 'Erro ao buscar a senha do usuário.' });
      }

      if (results.length === 0) {
        return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
      }

      const storedPasswordHash = results[0].senha;

      // Verificar se a senha atual está correta
      const passwordMatch = await bcrypt.compare(currentPassword, storedPasswordHash);
      if (!passwordMatch) {
        return res.status(401).json({ success: false, message: 'Senha incorreta.' });
      }

      // Atualizar o novo e-mail no banco de dados
      const updateQuery = 'UPDATE usuario SET email = ? WHERE idusuario = ?';
      db.query(updateQuery, [newEmail, userId], (err, result) => {
        if (err) {
          console.error('Erro ao atualizar o e-mail no banco de dados:', err);
          return res.status(500).json({ success: false, message: 'Erro ao atualizar o e-mail.' });
        }

        res.json({ success: true, message: 'E-mail alterado com sucesso.' });
      });
    });
});


// Servir arquivos estáticos (CSS, imagens, etc.)
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'css')));
app.use(express.static(path.join(__dirname, 'assets')));
app.use(express.static(path.join(__dirname, 'img')));
app.use(express.static(path.join(__dirname, 'html')));
app.use(express.static(path.join(__dirname, 'video')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
console.log('Servindo arquivos estáticos a partir da pasta public');



// Servir o arquivo HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/html/indexInicio.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '/html/indexSingIn.html'));
});
app.get('/cadastro', (req, res) => {
    res.sendFile(path.join(__dirname, '/html/indexCadastro.html'));
});
app.get('/word', (req, res) => {
    res.sendFile(path.join(__dirname, '/html/word.html'));
});

app.get('/video', (req, res) => {
    res.sendFile(path.join(__dirname, '/video'));
});


app.get('/pagaluno', (req, res) => {
    console.log('Sessão atual:', req.session); // Adicione este log
    if (!req.session.usuario) {
        res.redirect('/login');
        return;
    }
    res.sendFile(path.join(__dirname, '/html/pagaluno.html'));
});

app.use('/pagaluno', (req, res, next) => {
    if (!req.session.usuario) {
        return res.status(401).send({ message: 'Você precisa se registrar ou logar para acessar esta página.' });
    }
    next();
});

app.get('/getUsuarioId', (req, res) => {
    if (req.session.usuario) {
        res.json({ usuarioId: req.session.usuario.idusuario });  // Retorna o ID do usuário logado
    } else {
        res.status(401).json({ message: 'Usuário não está logado' });
    }
});

// Rota para login de dados com verificação da senha criptografada
app.post('/login', (req, res) => {
    const { email, senha } = req.body;
    
    // Verificar se o e-mail existe
    const queryVerificar = 'SELECT * FROM usuario WHERE email = ?';
    db.query(queryVerificar, [email], (err, results) => {
        if (err) {
            throw err;
        }

        if (results.length > 0) {
            const usuario = results[0];

            // Comparar a senha fornecida com a senha criptografada no banco de dados
            bcrypt.compare(senha, usuario.senha, (err, isMatch) => {
                if (err) {
                    console.error('Erro ao comparar senhas:', err);
                    return res.status(500).json({ message: 'Erro no servidor.' });
                }
            
                if (isMatch) {
                    console.log('Usuário logado:', usuario); // Log do usuário logado
                    req.session.usuario = usuario; // Armazena o usuário na sessão
                    res.json({ success: true });
                } else {
                    console.log('Senha incorreta'); // Log para senhas incorretas
                    res.json({ success: false, message: 'Senha incorreta!' });
                }
            });
        } else {
            res.json({ success: false, message: 'E-mail não encontrado!' }); // E-mail não cadastrado
        }
    });
});
// Rota para cadastrar dados com senha criptografada
app.post('/cadastrar', (req, res) => {
    const { nome, email, senha } = req.body;

    // Verificar se o e-mail já está cadastrado
    const queryVerificar = 'SELECT * FROM usuario WHERE email = ?';
    db.query(queryVerificar, [email], (err, results) => {
        if (err) {
            throw err;
        }
        if (results.length > 0) {
            return res.json({ message: 'Usuário já cadastrado!' });
        }

        // Criptografar a senha antes de armazená-la
        bcrypt.hash(senha, 10, (err, hash) => {
            if (err) {
                console.error('Erro ao criptografar a senha:', err);
                return res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
            }

            // Inserir o novo usuário com a senha criptografada
            const query = 'INSERT INTO usuario (nome, email, senha) VALUES (?, ?, ?)';
            db.query(query, [nome, email, hash], (err, results) => {
                if (err) {
                    throw err;
                }
                res.json({ message: 'Dados cadastrados com sucesso!' });
            });
        });
    });
});

//verificar cadastros
app.post('/verificarCadastro', (req, res) => {
    const { email } = req.body;
    const query = 'SELECT * FROM usuario WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            throw err;
        }
        if (results.length > 0) {
            res.json({ message: 'Usuário já cadastrado!' });
        } else {
            res.json({ message: 'Usuário não cadastrado!' });
        }
    });
});

// Rota para salvar o progresso no banco de dados
app.post('/salvarProgresso', (req, res) => {
    const { usuarioId, cursoId, videoIdAtual, totalVideos } = req.body;

    // Validar se todos os dados necessários foram enviados
    if (!usuarioId || !cursoId || !videoIdAtual || !totalVideos) {
        return res.status(400).json({ message: 'Dados insuficientes para salvar progresso.' });
    }

    // Validar para que o número de vídeos assistidos não exceda o total de vídeos
    const queryCheck = 'SELECT * FROM progresso_usuario WHERE usuarioId = ? AND cursoId = ?';
    
    db.query(queryCheck, [usuarioId, cursoId], (err, results) => {
        if (err) {
            console.error('Erro ao verificar progresso:', err);
            return res.status(500).json({ message: 'Erro ao verificar progresso.' });
        }

        let videosAssistidos = results.length > 0 ? results[0].videosAssistidos : 0;

        // Verificar se o vídeo atual já foi assistido
        const queryCheckVideo = 'SELECT * FROM videos_assistidos WHERE usuarioId = ? AND cursoId = ? AND videoId = ?';
        db.query(queryCheckVideo, [usuarioId, cursoId, videoIdAtual], (err, videoResults) => {
            if (err) {
                console.error('Erro ao verificar se o vídeo foi assistido:', err);
                return res.status(500).json({ message: 'Erro ao verificar se o vídeo foi assistido.' });
            }

            if (videoResults.length > 0) {
                // O vídeo já foi assistido
                console.log('Vídeo já assistido. Progresso não será atualizado.');
                return res.json({ message: 'Vídeo já assistido. Progresso não atualizado.', progresso: results[0]?.progresso || 0 });
            } else {
                // Adicionar o vídeo à tabela de vídeos assistidos
                const queryInsertVideo = 'INSERT INTO videos_assistidos (usuarioId, cursoId, videoId) VALUES (?, ?, ?)';
                db.query(queryInsertVideo, [usuarioId, cursoId, videoIdAtual], (err, result) => {
                    if (err) {
                        console.error('Erro ao registrar vídeo assistido:', err);
                        return res.status(500).json({ message: 'Erro ao registrar vídeo assistido.' });
                    }

                    // Atualizar o número de vídeos assistidos
                    videosAssistidos += 1;

                    // Calcular a porcentagem de progresso
                    const progresso = Math.min((videosAssistidos / totalVideos) * 100, 100);

                    if (results.length > 0) {
                        // Atualizar o progresso existente
                        const queryUpdate = 'UPDATE progresso_usuario SET videosAssistidos = ?, progresso = ? WHERE usuarioId = ? AND cursoId = ?';
                        db.query(queryUpdate, [videosAssistidos, progresso, usuarioId, cursoId], (err, result) => {
                            if (err) {
                                console.error('Erro ao atualizar progresso:', err);
                                return res.status(500).json({ message: 'Erro ao atualizar progresso.' });
                            }
                            res.json({ message: 'Progresso atualizado com sucesso!', progresso });
                        });
                    } else {
                        // Inserir um novo registro de progresso
                        const queryInsert = 'INSERT INTO progresso_usuario (usuarioId, cursoId, videosAssistidos, progresso) VALUES (?, ?, ?, ?)';
                        db.query(queryInsert, [usuarioId, cursoId, videosAssistidos, progresso], (err, result) => {
                            if (err) {
                                console.error('Erro ao salvar progresso:', err);
                                return res.status(500).json({ message: 'Erro ao salvar progresso.' });
                            }
                            res.json({ message: 'Progresso salvo com sucesso!', progresso });
                        });
                    }
                });
            }
        });
    });
});

// Rota para obter o progresso do usuário
app.get('/getProgresso', (req, res) => {
    const { usuarioId, cursoId } = req.query;

    // Verificar se os parâmetros foram fornecidos
    if (!usuarioId || !cursoId) {
        return res.status(400).json({ message: 'ID do usuário ou do curso não fornecido.' });
    }

    // Consulta para buscar o progresso do banco de dados
    const query = `
        SELECT pu.videosAssistidos, pu.progresso, COUNT(va.videoId) AS videosAssistidos
        FROM progresso_usuario pu
        LEFT JOIN videos_assistidos va ON va.usuarioId = pu.usuarioId AND va.cursoId = pu.cursoId
        WHERE pu.usuarioId = ? AND pu.cursoId = ?
        GROUP BY pu.videosAssistidos, pu.progresso
    `;
    db.query(query, [usuarioId, cursoId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Erro ao buscar progresso.' });
        }

        if (results.length > 0) {
            const progresso = results[0];
            res.json({
                videosAssistidos: progresso.videosAssistidos || 0, // Quantidade de vídeos assistidos
                progresso: Math.min(progresso.progresso, 100) // Limitar a 100%
            });
        } else {
            // Se não houver progresso salvo, retornar valores zerados
            res.json({ videosAssistidos: 0, progresso: 0 });
        }
    });
});

// Rota para verificar se o usuário concluiu o curso
app.post('/user/checkCompletion', (req, res) => {
    const { usuarioId, cursoId } = req.body;

    // Verificar se os parâmetros foram fornecidos
    if (!usuarioId || !cursoId) {
        return res.status(400).json({ message: 'ID do usuário ou do curso não fornecido.' });
    }

    // Consulta para buscar o progresso do curso no banco de dados
    const query = `
        SELECT pu.progresso
        FROM progresso_usuario pu
        WHERE pu.usuarioId = ? AND pu.cursoId = ?
    `;
    
    db.query(query, [usuarioId, cursoId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Erro ao verificar a conclusão do curso.' });
        }

        if (results.length > 0) {
            const progresso = results[0].progresso;

            // Verificar se o progresso do curso é de 100%
            if (progresso >= 100) {
                return res.json({ success: true, isCompleted: true });
            } else {
                return res.json({ success: true, isCompleted: false });
            }
        } else {
            // Se não houver progresso salvo, retornar que o curso não foi concluído
            res.json({ success: true, isCompleted: false });
        }
    });
});


// POST: Adicionar ou remover curso dos favoritos (usando callbacks)
app.post('/user/favorite', (req, res) => {
    const userId = req.session.usuario.idusuario; // ID do usuário logado
    const courseId = req.body.courseId;

    // Verifique se o curso já está favoritado
    db.query('SELECT * FROM favorites WHERE usuario_id = ? AND curso_id = ?', [userId, courseId], (err, isFavorited) => {
        if (err) {
            console.error('Erro ao verificar favorito:', err);
            return res.status(500).json({ success: false, message: 'Erro no servidor ao verificar favoritos.' });
        }

        if (isFavorited.length > 0) {
            // Se já estiver favoritado, remova-o
            db.query('DELETE FROM favorites WHERE usuario_id = ? AND curso_id = ?', [userId, courseId], (err) => {
                if (err) {
                    console.error('Erro ao remover favorito:', err);
                    return res.status(500).json({ success: false, message: 'Erro ao remover favorito.' });
                }
                res.json({ success: true, isFavorited: false });
            });
        } else {
            // Caso contrário, adicione-o aos favoritos
            db.query('INSERT INTO favorites (usuario_id, curso_id) VALUES (?, ?)', [userId, courseId], (err) => {
                if (err) {
                    console.error('Erro ao adicionar favorito:', err);
                    return res.status(500).json({ success: false, message: 'Erro ao adicionar favorito.' });
                }
                res.json({ success: true, isFavorited: true });
            });
        }
    });
});

// GET: Carregar os favoritos do usuário (usando callbacks)
app.get('/user/favorites', (req, res) => {
    const userId = req.session.usuario.idusuario; // ID do usuário logado

    db.query('SELECT curso_id FROM favorites WHERE usuario_id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Erro ao carregar favoritos:', err);
            return res.status(500).json({ success: false, message: 'Erro ao carregar favoritos.' });
        }   
        // Adicione este log para verificar a resposta do banco
        console.log('Favoritos retornados:', results);

        const favorites = results.map(row => row.curso_id);
        res.json({ success: true, favorites });
    });
});

app.post('/salvarAvaliacao', (req, res) => {
    const { usuarioId, cursoId, videoId, avaliacao } = req.body;

    // Executa a query
    db.query('INSERT INTO avaliacoes (usuarioId, cursoId, videoId, avaliacao) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE avaliacao = ?', [usuarioId, cursoId, videoId,avaliacao, avaliacao], (err, results) => {
        if (err) {
            console.error('Erro ao salvar avaliação:', err);
            res.status(500).json({ success: false, message: 'Erro ao salvar avaliação.' });
        } else {
            res.status(200).json({ success: true, message: 'Avaliação salva com sucesso!' });
        }
    });

});

app.get('/getAvaliacao', (req, res) => {
    const { usuarioId, cursoId, videoId } = req.query;

    db.query('SELECT avaliacao FROM avaliacoes WHERE usuarioId = ? AND cursoId = ? AND videoId = ?', [usuarioId, cursoId, videoId], (err, results) => {
        if (err) {
            console.error('Erro ao buscar avaliação:', err);
            res.status(500).json({ success: false, message: 'Erro ao buscar avaliação.' });
        } else if (results.length > 0) {
            res.status(200).json({ success: true, avaliacao: results[0].avaliacao });
        } else {
            res.status(404).json({ success: false, message: 'Avaliação não encontrada.' });
        }
    });

});

// verificar login
app.get('/verificarLogin', (req, res) => {
    if (req.session.usuario) {
        res.json({ logado: true });
    } else {
        res.json({ logado: false });
    }
});



app.get('/getData', (req, res) => {
    const userId = req.session.usuario?.idusuario; // Supondo que o ID do usuário está na sessão (ou substitua por JWT, etc.)
    
    if (!userId) {
        return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    const query = 'SELECT nome, email FROM usuario WHERE idusuario = ?'; 

    // Passa o ID do usuário de forma segura para o query
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Erro ao consultar o banco de dados:', err);
            return res.status(500).json({ error: 'Erro ao buscar os dados do usuário' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Retorna o nome e o email do usuário como JSON
        res.json({
            nome: results[0].nome,
            email: results[0].email
        });
    });
});



app.post('/update-username', (req, res) => {
    const newUserName = req.body.name;
    const userId = req.session.usuario.idusuario; // Supondo que você tenha o ID do usuário na sessão
  
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Usuário não autenticado' });
    }
  
    const query = 'UPDATE usuario SET nome = ? WHERE idusuario = ?';
  
    db.query(query, [newUserName, userId], (err, results) => {
      if (err) {
        console.error('Erro ao atualizar o nome:', err);
        return res.status(500).json({ success: false, message: 'Erro ao atualizar o nome' });
      }
  
      if (results.affectedRows > 0) {
        res.json({ success: true, message: 'Nome atualizado com sucesso' });
      } else {
        res.status(404).json({ success: false, message: 'Usuário não encontrado' });
      }
    });
  });


// Rota para atualizar dados
app.put('/update/:idusuario', (req, res) => {
    const { idusuario } = req.params;
    const { nome, email, senha } = req.body;

    if (senha) {
        bcrypt.hash(senha, 10, (err, hash) => {
            if (err) {
                return res.status(500).json({ message: 'Erro ao criptografar a senha.' });
            }

            const query = 'UPDATE usuario SET nome = ?, email = ?, senha = ? WHERE idusuario = ?';
            db.query(query, [nome, email, hash, idusuario], (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Erro ao atualizar os dados.' });
                }
                res.json({ message: 'Dados atualizados com sucesso!' });
            });
        });
    } else {
        // Se a senha não foi alterada, não deve ser atualizada
        const query = 'UPDATE usuario SET nome = ?, email = ? WHERE idusuario = ?';
        db.query(query, [nome, email, idusuario], (err, result) => {
            if (err) {
                return res.status(500).json({ message: 'Erro ao atualizar os dados.' });
            }
            res.json({ message: 'Dados atualizados com sucesso!' });
        });
    }
});

// Rota para deletar dados
app.delete('/delete/:idusuario', (req, res) => {
    const { idusuario } = req.params;
    const query = 'DELETE FROM usuario WHERE idusuario = ?';
    db.query(query, [idusuario], (err, result) => {
        if (err) {
            throw err;
        }
        res.json({ message: 'Dados deletados com sucesso!' });
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});