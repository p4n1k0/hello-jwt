const jwt = require('jsonwebtoken');

const { JWT_SECRET } = process.env;

function extractToken(bearerToken) {
    return bearerToken.split(' ')[1]
}

module.exports = (req, res, next) => {
    /* Buscamos o token no header `Authorization` */
    const bearerToken = req.header('Authorization');

    // /* Separamos o prefixo "Bearer" do token e retornamos apenas o valor do token /*
    const token = extractToken(bearerToken);

    /* Caso o token não exista */
    if (!token) {
        /* Criamos um novo objeto de erro */
        const err = new Error('Token not found');
        /* Damos o status 401 ao erro */
        err.statusCode = 401;
        /* Enviamos o erro para ser tratado pelo middleware de erro */
        return next(err);
    }

    /* Realizamos uma tentativa de validar o token */
    try {
        /* Pedimos para que a biblioteca de JWT valide o token, mas antes separamos o valor retornado de 'Authorization' do prefixo "Bearer" e retornamos apenas o valor do token /*  
        */
        const payload = jwt.verify(token, JWT_SECRET);

        /* Caso não ocorra nenhum erro, significa que o token é válido e podemos continuar */

        /* Armazenamos os dados da pessoa no objeto de request */
        req.user = payload;

        return next();
    } catch (err) {
        /* Caso haja algum erro ao validar o token, adicionamos o status 401 a esse erro */
        err.statusCode = 401;
        /* E enviamos o erro para ser processador pelo middleware de erro. */
        return next(err);
    }
};
