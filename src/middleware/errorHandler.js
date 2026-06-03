function errorHandler(err, req, res, next) {
  const statusCode = err.status || err.statusCode || 500;
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    console.error('Unhandled server error:', err);
  } else {
    console.error('Unhandled server error:', err.message);
  }

  res.status(statusCode).json({
    success: false,
    message: isProduction && statusCode === 500
      ? 'Something went wrong'
      : err.message || 'Something went wrong',
    ...(!isProduction && { stack: err.stack })
  });
}

module.exports = errorHandler;
