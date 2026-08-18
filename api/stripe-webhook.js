const crypto = require('crypto');

const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// A Vercel precisa do corpo "cru" (sem parsear) pra verificar a assinatura do Stripe
module.exports.config = {
  api: {
    bodyParser: false,
  },
};

function lerCorpoBruto(req) {
  return new Promise((resolve, reject) => {
    const partes = [];
    req.on('data', (parte) => partes.push(Buffer.isBuffer(parte) ? parte : Buffer.from(parte)));
    req.on('end', () => resolve(Buffer.concat(partes)));
    req.on('error', reject);
  });
}

function assinaturaValida(payloadTexto, cabecalhoAssinatura, segredo) {
  if (!cabecalhoAssinatura) return false;
  const campos = cabecalhoAssinatura.split(',').reduce((acc, parte) => {
    const [chave, valor] = parte.split('=');
    acc[chave] = valor;
    return acc;
  }, {});
  const timestamp = campos['t'];
  const assinaturaRecebida = campos['v1'];
  if (!timestamp || !assinaturaRecebida) return false;

  const payloadAssinado = `${timestamp}.${payloadTexto}`;
  const assinaturaEsperada = crypto
    .createHmac('sha256', segredo)
    .update(payloadAssinado, 'utf8')
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(assinaturaEsperada, 'utf8'),
      Buffer.from(assinaturaRecebida, 'utf8')
    );
  } catch (e) {
    return false;
  }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  const corpoBruto = await lerCorpoBruto(req);
  const payloadTexto = corpoBruto.toString('utf8');
  const cabecalhoAssinatura = req.headers['stripe-signature'];

  if (!assinaturaValida(payloadTexto, cabecalhoAssinatura, STRIPE_WEBHOOK_SECRET)) {
    res.status(400).send('Assinatura inválida');
    return;
  }

  let evento;
  try {
    evento = JSON.parse(payloadTexto);
  } catch (e) {
    res.status(400).send('Payload inválido');
    return;
  }

  if (evento.type === 'checkout.session.completed') {
    const session = evento.data.object;
    const userId = session.metadata && session.metadata.user_id;

    if (userId) {
      try {
        await fetch(`${SUPABASE_URL}/rest/v1/assinaturas?user_id=eq.${userId}`, {
          method: 'PATCH',
          headers: {
            apikey: SUPABASE_SERVICE_ROLE_KEY,
            Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify({
            pago: true,
            atualizado_em: new Date().toISOString(),
          }),
        });
      } catch (e) {
        console.error('Erro ao atualizar assinatura no Supabase:', e);
        res.status(500).json({ error: 'Falha ao atualizar assinatura' });
        return;
      }
    }
  }

  res.status(200).json({ received: true });
};
