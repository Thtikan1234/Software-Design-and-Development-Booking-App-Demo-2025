import React, { useState } from 'react';
import axios from 'axios';
import API_URL from '../config';

const BookingForm = () => {
  const [formData, setFormData] = useState({
    fullname: '', email: '', phone: '',
    checkin: '', checkout: '', roomtype: '', guests: 1,
  });
  const [error, setError]     = useState('');
  const [success, setSuccess] = useState('');

  const maxGuests = { standard: 2, deluxe: 3, suite: 4 };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');

    const checkin  = new Date(formData.checkin);
    const checkout = new Date(formData.checkout);
    const today    = new Date(); today.setHours(0, 0, 0, 0);

    if (checkin < today)        { setError('กรุณาเลือกวันเช็คอินที่ยังไม่ผ่านมา'); return; }
    if (checkout <= checkin)    { setError('วันเช็คเอาท์ต้องมาหลังวันเช็คอิน'); return; }
    if (!/^[0-9]{10}$/.test(formData.phone)) { setError('กรุณากรอกเบอร์โทรศัพท์ 10 หลัก'); return; }

    const days      = Math.ceil((checkout - checkin) / (1000 * 60 * 60 * 24));
    const roomNames = { standard: 'ห้องมาตรฐาน', deluxe: 'ห้องดีลักซ์', suite: 'ห้องสวีท' };
    const summary   =
      `สรุปการจอง:\n- ชื่อ: ${formData.fullname}\n` +
      `- ห้อง: ${roomNames[formData.roomtype]}\n` +
      `- จำนวนวัน: ${days} วัน\n- ผู้เข้าพัก: ${formData.guests} ท่าน`;

    if (window.confirm(summary + '\n\nยืนยันการจอง?')) {
      try {
        await axios.post(`${API_URL}/api/bookings`, formData);
        setSuccess('จองห้องพักเรียบร้อยแล้ว');
        setFormData({ fullname: '', email: '', phone: '', checkin: '', checkout: '', roomtype: '', guests: 1 });
      } catch (err) {
        setError(err.response?.data?.error || 'เกิดข้อผิดพลาด');
      }
    }
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-center">จองห้องพัก</h2>

      {error   && <div className="bg-red-100   text-red-700   border border-red-400   px-4 py-3 rounded mb-4">{error}</div>}
      {success && <div className="bg-green-100 text-green-700 border border-green-400 px-4 py-3 rounded mb-4">{success}</div>}

      <form onSubmit={handleSubmit} className="space-y-4">
        {[
          { label: 'ชื่อ-นามสกุล:', name: 'fullname', type: 'text' },
          { label: 'อีเมล:',        name: 'email',    type: 'email' },
          { label: 'เบอร์โทรศัพท์:', name: 'phone',    type: 'tel' },
        ].map(({ label, name, type }) => (
          <div key={name}>
            <label className="block text-gray-700 mb-2">{label}</label>
            <input type={type} name={name} value={formData[name]} onChange={handleChange}
              className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500" required />
          </div>
        ))}

        <div>
          <label className="block text-gray-700 mb-2">วันที่เช็คอิน:</label>
          <input type="date" name="checkin" value={formData.checkin} onChange={handleChange}
            min={new Date().toISOString().split('T')[0]}
            className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500" required />
        </div>

        <div>
          <label className="block text-gray-700 mb-2">วันที่เช็คเอาท์:</label>
          <input type="date" name="checkout" value={formData.checkout} onChange={handleChange}
            min={formData.checkin}
            className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500" required />
        </div>

        <div>
          <label className="block text-gray-700 mb-2">ประเภทห้องพัก:</label>
          <select name="roomtype" value={formData.roomtype} onChange={handleChange}
            className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500" required>
            <option value="">กรุณาเลือกประเภทห้องพัก</option>
            <option value="standard">ห้องมาตรฐาน (สูงสุด 2 ท่าน)</option>
            <option value="deluxe">ห้องดีลักซ์ (สูงสุด 3 ท่าน)</option>
            <option value="suite">ห้องสวีท (สูงสุด 4 ท่าน)</option>
          </select>
        </div>

        <div>
          <label className="block text-gray-700 mb-2">จำนวนผู้เข้าพัก:</label>
          <input type="number" name="guests" value={formData.guests} onChange={handleChange}
            min="1" max={formData.roomtype ? maxGuests[formData.roomtype] : 1}
            className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500" required />
        </div>

        <button type="submit"
          className="w-full bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600 transition-colors">
          จองห้องพัก
        </button>
      </form>
    </div>
  );
};

export default BookingForm;