/** Local checks for an uploaded project ZIP (no server call). */
export function validateZipFile(file: File): { valid: boolean; error?: string } {
  // 检查文件类型
  if (!file.type.includes('zip') && !file.name.toLowerCase().endsWith('.zip')) {
    return { valid: false, error: '请上传ZIP格式的文件' };
  }

  // 检查文件大小 (限制为500MB)
  const maxSize = 500 * 1024 * 1024;
  if (file.size > maxSize) {
    return { valid: false, error: '文件大小不能超过500MB' };
  }

  return { valid: true };
}
