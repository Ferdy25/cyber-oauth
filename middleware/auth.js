const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');


async function readJSONFile(filename) {
  const data = await fs.readFile(path.join(__dirname, '..', 'data', filename), 'utf8');
  return JSON.parse(data);
}


const authenticateJWT = async (req, res, next) => {
  try {
    let token = null;
    
    if (req.query.token) {
      token = req.query.token;
      console.log('✅ Token dari query param');
    }
    else if (req.cookies?.token) {
      token = req.cookies.token;
      console.log('✅ Token dari cookie');
    }
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
      console.log('✅ Token dari Authorization header');
    }

    console.log('🔑 Token:', token ? token.substring(0, 30) + '...' : '❌ TIDAK ADA');

    if (!token) {
      console.log('🔄 Redirect ke login (no token)');
      if (req.accepts('html')) {
        return res.redirect('/');
      }
      return res.status(401).json({ error: 'Token tidak ditemukan, login dulu bro!' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const users = await readJSONFile('users.json');
    const user = users.find(u => u.id === decoded.userId);

    if (!user) {
      console.log('❌ User tidak ditemukan');
      if (req.accepts('html')) {
        return res.redirect('/');
      }
      return res.status(401).json({ error: 'User tidak ditemukan' });
    }

    console.log('✅ Authenticated:', user.username, '| Role:', user.role);
    req.user = user;
    next();
  } catch (error) {
    console.error('❌ JWT Error:', error.message);
    if (req.accepts('html')) {
      return res.redirect('/');
    }
    return res.status(401).json({ error: 'Token invalid atau expired' });
  }
};

const checkRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Akses ditolak! Role tidak sesuai.',
        required_roles: roles,
        your_role: req.user.role
      });
    }
    next();
  };
};

const checkDocumentAccess = async (req, res, next) => {
  try {
    const documents = await readJSONFile('documents.json');
    const docId = parseInt(req.params.id);
    const document = documents.find(d => d.id === docId);

    if (!document) {
      return res.status(404).json({ error: 'Dokumen tidak ditemukan' });
    }

    const user = req.user;
    let hasAccess = false;
    let accessReason = '';

    if (user.role === 'admin') {
      hasAccess = true;
      accessReason = 'Admin memiliki akses penuh';
    }
    else if (document.owner_id === user.id) {
      hasAccess = true;
      accessReason = 'Anda adalah pemilik dokumen';
    }
    else if (user.role === 'manager' && document.department === user.department) {
      hasAccess = true;
      accessReason = 'Manager dapat mengakses dokumen departemen';
    }
    else if (user.clearance_level >= document.sensitivity_level) {
      hasAccess = true;
      accessReason = 'Clearance level mencukupi';
    }
    if (hasAccess && document.sensitivity_level >= 4 && user.subscription !== 'premium') {
      hasAccess = false;
      accessReason = 'Dokumen premium memerlukan langganan premium';
    }

    if (!hasAccess) {
      return res.status(403).json({
        error: 'Akses ditolak berdasarkan atribut',
        detail: {
          user_attributes: {
            role: user.role,
            department: user.department,
            clearance: user.clearance_level,
            subscription: user.subscription
          },
          document_attributes: {
            department: document.department,
            sensitivity: document.sensitivity_level,
            owner_id: document.owner_id
          }
        }
      });
    }

    req.document = document;
    next();
  } catch (error) {
    next(error);
  }
};


const combinedAccess = (options) => {
  return async (req, res, next) => {
    try {
      const { allowedRoles, requiredAttributes } = options;
      
      if (!allowedRoles.includes(req.user.role)) {
        return res.status(403).json({
          error: 'RBAC Check GAGAL',
          detail: 'Role tidak diizinkan untuk aksi ini'
        });
      }

      const documents = await readJSONFile('documents.json');
      const document = documents.find(d => d.id === parseInt(req.params.id));
      
      if (!document) {
        return res.status(404).json({ error: 'Dokumen tidak ditemukan' });
      }

      if (requiredAttributes.sameDepartment && 
          req.user.department !== document.department) {
        return res.status(403).json({
          error: 'ABAC Check GAGAL',
          detail: 'Dokumen harus dari departemen yang sama'
        });
      }

      if (requiredAttributes.minClearance && 
          req.user.clearance_level < requiredAttributes.minClearance) {
        return res.status(403).json({
          error: 'ABAC Check GAGAL',
          detail: 'Clearance level tidak mencukupi'
        });
      }

      if (requiredAttributes.premiumOnly && 
          req.user.subscription !== 'premium') {
        return res.status(403).json({
          error: 'ABAC Check GAGAL',
          detail: 'Memerlukan langganan premium'
        });
      }

      req.document = document;
      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = {
  authenticateJWT,
  checkRole,
  checkDocumentAccess,
  combinedAccess,
  readJSONFile
};